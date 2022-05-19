require('dotenv').config();
const { ethers, upgrades } = require("hardhat");


const NEAR_TOKEN_FACTORY = Buffer.from(process.env.NEAR_TOKEN_FACTORY, 'utf-8');
const PROVER_ADDRESS = process.env.PROVER_ADDRESS;
const MIN_BLOCK_ACCEPTANCE_HEIGHT = parseInt(process.env.MIN_BLOCK_ACCEPTANCE_HEIGHT);

async function main() {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = await upgrades.deployProxy(BridgeTokenFactoryContract, [NEAR_TOKEN_FACTORY, PROVER_ADDRESS, MIN_BLOCK_ACCEPTANCE_HEIGHT], { initializer: 'initialize' })
    await BridgeTokenFactory.deployed();
    console.log(`BridgeTokenFactory deployed at ${BridgeTokenFactory.address}`);
}

main();