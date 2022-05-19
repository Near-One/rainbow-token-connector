require('dotenv').config();
const { ethers, upgrades } = require("hardhat");

const PROXY_ADDRESS = process.env.BRIDGE_TOKEN_FACTORY_PROXY_ADDRESS;


async function main() {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = await upgrades.upgradeProxy(PROXY_ADDRESS, BridgeTokenFactoryContract);
    console.log(`Bridge token factory upgraded: ${BridgeTokenFactory}`);
}

main();