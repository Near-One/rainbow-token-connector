require('dotenv').config();
const { ethers } = require("hardhat");


const NEAR_TOKEN_LOCKER = Buffer.from(process.env.NEAR_TOKEN_LOCKER, 'utf-8');
const PROVER_ADDRESS = process.env.PROVER_ADDRESS;
const MIN_BLOCK_ACCEPTANCE_HEIGHT = parseInt(process.env.MIN_BLOCK_ACCEPTANCE_HEIGHT);

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying contracts with the account:", deployer.address);
    console.log("Account balance:", (await deployer.getBalance()).toString())

    const ProofConsumerContract = await ethers.getContractFactory("ProofConsumer");
    const proofConsumer = await ProofConsumerContract.deploy(NEAR_TOKEN_LOCKER, PROVER_ADDRESS, MIN_BLOCK_ACCEPTANCE_HEIGHT)
    console.log(`ProofConsumer deployed at ${proofConsumer.address}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
