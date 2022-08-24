require('dotenv').config();
const { ethers } = require("hardhat");

const TOKEN_FACTORY_ADDRESS = process.env.TOKEN_FACTORY_ADDRESS;
const NEAR_TOKEN_ID = process.env.NEAR_TOKEN_ID;

async function main() {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(TOKEN_FACTORY_ADDRESS);
    console.log(`Upgrade token ${NEAR_TOKEN_ID}`);
    console.log(`Token proxy address`, await BridgeTokenFactory.nearToEthToken(NEAR_TOKEN_ID));
    const BridgeTokenV2Instance = await ethers.getContractFactory("BridgeTokenV2");
    const BridgeTokenV2 = await (await BridgeTokenV2Instance.deploy()).deployed();
    console.log(`BridgeTokenV2 deployed at ${BridgeTokenV2.address}`);
    const tx = await BridgeTokenFactory.upgradeToken(NEAR_TOKEN_ID, BridgeTokenV2.address);
    const receipt = await tx.wait();
    console.log("Token upgraded at tx hash", receipt.transactionHash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
