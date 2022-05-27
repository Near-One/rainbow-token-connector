require('dotenv').config();
const { ethers } = require("hardhat");


const NEAR_TOKEN_FACTORY = Buffer.from(process.env.NEAR_TOKEN_FACTORY, 'utf-8');
const NEAR_TOKEN_ID = process.env.NEAR_TOKEN_ID;

async function main() {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(NEAR_TOKEN_FACTORY);
    const BridgeTokenV2Instance = await ethers.getContractFactory("BridgeTokenV2");
    const BridgeTokenV2 = await (await BridgeTokenV2Instance.deploy()).deployed();
    console.log(`BridgeTokenV2 deployed at ${BridgeTokenV2.address}`);
    const upgradeToken = await BridgeTokenFactory.upgradeToken(NEAR_TOKEN_ID, BridgeTokenV2.address);
    console.log("Token upgraded");
}

main();