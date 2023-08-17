require("dotenv").config();
const { ethers, upgrades } = require("hardhat");

async function deploy({
  signer,
  wNearAddress,
  siloAccountId,
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
    [wNearAddress, siloAccountId],
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

exports.deploy = deploy;
exports.upgrade = upgrade;
