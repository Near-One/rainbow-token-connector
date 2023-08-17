require("dotenv").config();
require("@nomicfoundation/hardhat-ethers");
require("@openzeppelin/hardhat-upgrades");

const AURORA_PRIVATE_KEY = process.env.AURORA_PRIVATE_KEY;

task("deploy", "Deploy silo to silo proxy contract")
  .addParam("silo", "Config file name without extension")
  .setAction(async (taskArgs, hre) => {
    const { deploy } = require("./utils/scripts.js");
    const [deployer] = await hre.ethers.getSigners();
    const config = require(`./configs/${taskArgs.silo}.json`);

    await hre.run("compile");
    await deploy(
      deployer,
      config.wNearAddress,
      config.siloAccountId,
      config.auroraSdkAddress,
      config.auroraUtilsAddress,
    );
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
