require("dotenv").config();
const { ethers, upgrades } = require("hardhat");

async function deploy({
  signer,
  wNearAddress,
  siloAccountId,
  nativeTokenAccountId,
  auroraSdkAddress,
  auroraUtilsAddress,
}) {
  console.log("Deploying contracts with the account:", signer.address);
  console.log(
    "Account balance:",
    (await signer.provider.getBalance(signer.address)).toString(),
  );

  const SiloToSiloContract = (
    await ethers.getContractFactory("SiloToSilo", {
      libraries: {
        AuroraSdk: auroraSdkAddress,
        Utils: auroraUtilsAddress,
      },
    })
  ).connect(signer);

  let proxy = await upgrades.deployProxy(
    SiloToSiloContract,
    [wNearAddress, siloAccountId, nativeTokenAccountId],
    {
      initializer: "initialize",
      unsafeAllowLinkedLibraries: true,
      gasLimit: 6000000,
    },
  );
  await proxy.waitForDeployment();

  console.log("SiloToSilo proxy deployed to: ", await proxy.getAddress());
  console.log(
    "SiloToSilo impl deployed to: ",
    await upgrades.erc1967.getImplementationAddress(await proxy.getAddress()),
  );
}

async function deploySDK({ signer }) {
  let utilsLib = await ethers.deployContract("Utils", { signer });
  await utilsLib.waitForDeployment();
  console.log("Utils lib deployed to: ", await utilsLib.getAddress());

  let codecLib = await ethers.deployContract("Codec", { signer });
  await codecLib.waitForDeployment();
  console.log("Codec lib deployed to: ", await codecLib.getAddress());

  const sdkLib = await ethers.deployContract("AuroraSdk", {
    signer,
    libraries: {
      Utils: await utilsLib.getAddress(),
      Codec: await codecLib.getAddress(),
    },
  });
  await sdkLib.waitForDeployment();
  console.log("SDK lib deployed to: ", await sdkLib.getAddress());
}

async function upgrade({
  signer,
  proxyAddress,
  auroraSdkAddress,
  auroraUtilsAddress,
}) {
  console.log("Upgrading contracts with the account:", signer.address);
  console.log(
      "Account balance:",
      (await signer.provider.getBalance(signer.address)).toString(),
  );

  const SiloToSiloContract = (
      await ethers.getContractFactory("SiloToSilo", {
        libraries: {
          AuroraSdk: auroraSdkAddress,
          Utils: auroraUtilsAddress,
        },
      })
  ).connect(signer);

  console.log(
      "Current implementation address:",
      await upgrades.erc1967.getImplementationAddress(proxyAddress),
  );
  console.log("Upgrade SiloToSilo contract, proxy address", proxyAddress);
  const proxy = await upgrades.upgradeProxy(proxyAddress, SiloToSiloContract, {
    unsafeAllowLinkedLibraries: true,
    gasLimit: 6000000,
  });
  await proxy.waitForDeployment();

  console.log(
      "SiloToSilo impl deployed to: ",
      await upgrades.erc1967.getImplementationAddress(await proxy.getAddress()),
  );
}

async function registerToken(signer, config, proxy, auroraTokenAddress) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
  await wnear.approve(proxy, "2000000000000000000000000");

  await siloToSilo.registerToken(auroraTokenAddress);
}

async function getTokenNearAccountId(signer, config, proxy, auroraTokenAddress) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);
  console.log("Near Account Id for Token: ", await siloToSilo.getTokenAccountId(auroraTokenAddress));
}

async function storageDeposit(signer, config, proxy, auroraTokenAddress) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
  await wnear.approve(proxy, "12500000000000000000000");

  await siloToSilo.storageDeposit(auroraTokenAddress, "12500000000000000000000");
}


async function isStorageRegistered(signer, config, proxy, auroraTokenAddress) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  console.log("Is Storage Registered: ", await siloToSilo.isStorageRegistered(auroraTokenAddress));
}

async function safeFtTransferCallToNear(signer, config, proxy, auroraTokenAddress, receiverId, amount, msg) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
  await wnear.transfer(siloToSilo, 1);

  const token = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
  await token.approve(proxy, amount);

  await siloToSilo.safeFtTransferCallToNear(auroraTokenAddress, amount, receiverId, msg);
}

async function recipientStorageDeposit(signer, config, proxy, auroraTokenAddress, receiverId) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
  await wnear.approve(proxy, "12500000000000000000000");

  await siloToSilo.recipientStorageDeposit(auroraTokenAddress, "12500000000000000000000", receiverId);
}

async function isRecipientStorageRegistered(signer, config, proxy, auroraTokenAddress, receiverId) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  console.log("Is Storage Registered: ", await siloToSilo.isRecipientStorageRegistered(auroraTokenAddress, receiverId));
}

async function getUserBalance(signer, config, proxy, auroraTokenAddress) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  console.log("User balance: ", await siloToSilo.getUserBalance(auroraTokenAddress, signer.address));
}

async function withdraw(signer, config, proxy, auroraTokenAddress) {
  const siloToSilo = await getSiloToSiloContract(signer, config, proxy);

  const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
  await wnear.transfer(siloToSilo, 1);

  await siloToSilo.withdraw(auroraTokenAddress);
}

async function getSiloToSiloContract(signer, config, proxy) {
  console.log("Sending transaction with the account:", signer.address);

  const SiloToSilo = await hre.ethers.getContractFactory("SiloToSilo", {
    libraries: {
      "AuroraSdk": config.auroraSdkAddress,
      "Utils": config.auroraUtilsAddress
    },
  });

  return SiloToSilo
      .attach(proxy)
      .connect(signer);
}

exports.deploy = deploy;
exports.upgrade = upgrade;
exports.registerToken = registerToken;
exports.getTokenNearAccountId = getTokenNearAccountId;
exports.storageDeposit = storageDeposit;
exports.isStorageRegistered = isStorageRegistered;
exports.safeFtTransferCallToNear = safeFtTransferCallToNear;
exports.recipientStorageDeposit = recipientStorageDeposit;
exports.isRecipientStorageRegistered = isRecipientStorageRegistered;
exports.getUserBalance = getUserBalance;
exports.withdraw = withdraw;
exports.deploySDK = deploySDK;
