require('dotenv').config();
const { ethers, upgrades } = require("hardhat");

const PROOF_CONSUMER_ADDRESS = process.env.PROOF_CONSUMER_ADDRESS;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
  const BridgeTokenFactory = await upgrades.deployProxy(BridgeTokenFactoryContract, [PROOF_CONSUMER_ADDRESS], { initializer: 'initialize' })
  await BridgeTokenFactory.deployed();
  console.log(`BridgeTokenFactory deployed at ${BridgeTokenFactory.address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });