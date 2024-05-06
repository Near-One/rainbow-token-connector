require('dotenv').config();
const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  const BridgeTokenContractFactory = await ethers.getContractFactory("BridgeToken");
  const BridgeTokenContract = await BridgeTokenContractFactory.deploy();
  await BridgeTokenContract.deployed();
  console.log(`BridgeTokenContract deployed at ${BridgeTokenContract.address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
