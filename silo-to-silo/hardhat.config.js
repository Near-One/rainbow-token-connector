require("dotenv").config();
require("@nomicfoundation/hardhat-ethers");
require("@openzeppelin/hardhat-upgrades");

const AURORA_PRIVATE_KEY = process.env.AURORA_PRIVATE_KEY;

task("deploy", "Deploy silo to silo proxy contract")
  .addParam("silo", "Config file name without extension")
  .setAction(async (taskArgs, hre) => {
    const { deploy } = require("./utils/scripts.js");
    const [signer] = await hre.ethers.getSigners();
    const config = require(`./configs/${taskArgs.silo}.json`);

    await hre.run("compile");
    await deploy({
      signer,
      wNearAddress: config.wNearAddress,
      siloAccountId: config.siloAccountId,
      nativeTokenAccountId: config.siloAccountId,
      auroraSdkAddress: config.auroraSdkAddress,
      auroraUtilsAddress: config.auroraUtilsAddress,
    });
  });

task("upgrade", "Upgrade silo to silo proxy contract")
  .addParam("silo", "Config file name without extension")
  .addParam("proxy", "Current proxy address of the SiloToSilo contract")
  .setAction(async (taskArgs, hre) => {
    const { upgrade } = require("./utils/scripts.js");
    const [signer] = await hre.ethers.getSigners();
    const config = require(`./configs/${taskArgs.silo}.json`);

    await hre.run("compile");
    await upgrade({
      signer,
      proxyAddress: taskArgs.proxy,
      auroraSdkAddress: config.auroraSdkAddress,
      auroraUtilsAddress: config.auroraUtilsAddress,
    });
  });

module.exports = {
  solidity: {
    version: "0.8.21",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    testnet_aurora: {
      url: "https://testnet.aurora.dev",
      accounts: [`0x${AURORA_PRIVATE_KEY}`],
      chainId: 1313161555,
    },
    develop_aurora: {
      url: "https://develop.rpc.testnet.aurora.dev:8545",
      accounts: [`0x${AURORA_PRIVATE_KEY}`],
    },
  },
  mocha: {
    timeout: 100000000,
  },
};
