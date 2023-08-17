require("dotenv").config();
const { ethers, upgrades } = require("hardhat");

async function deploy(
  deployer,
  wnearAuroraAddress,
  siloAccountId,
  auroraSdkAddress,
  auroraUtilsAddress,
) {
  console.log("Deploying contracts with the account:", deployer.address);
  console.log(
    "Account balance:",
    (await deployer.provider.getBalance(deployer.address)).toString(),
  );

  const SiloToSiloContract = (
    await ethers.getContractFactory("SiloToSilo", {
      libraries: {
        AuroraSdk: auroraSdkAddress,
        Utils: auroraUtilsAddress,
      },
    })
  ).connect(deployer);

  let proxy = await upgrades.deployProxy(
    SiloToSiloContract,
    [wnearAuroraAddress, siloAccountId],
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

exports.deploy = deploy;
