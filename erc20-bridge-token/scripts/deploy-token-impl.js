require("dotenv").config();
const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);
  const accountBalance = await deployer.provider.getBalance(deployer.address);
  console.log("Account balance:", accountBalance.toString());

  const BridgeTokenContractFactory =
    await ethers.getContractFactory("BridgeToken");
  const BridgeTokenContract = await BridgeTokenContractFactory.deploy();
  await BridgeTokenContract.waitForDeployment();
  console.log(`BridgeTokenContract deployed at ${await BridgeTokenContract.getAddress()}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
