require('dotenv').config();
const { ethers, upgrades } = require("hardhat");

const PROOF_CONSUMER_ADDRESS = process.env.PROOF_CONSUMER_ADDRESS;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());
  console.log("ProofConsumer address: ", PROOF_CONSUMER_ADDRESS);

  const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
  const BridgeTokenFactory = await upgrades.deployProxy(
    BridgeTokenFactoryContract,
    [PROOF_CONSUMER_ADDRESS],
    {
      initializer: 'initialize',
      timeout: 0
    }
  );
  await BridgeTokenFactory.deployed();
  console.log(`BridgeTokenFactory deployed at ${BridgeTokenFactory.address}`);
  console.log("Implementation address:", await upgrades.erc1967.getImplementationAddress(BridgeTokenFactory.address));

  console.log("Transfer ProofConsumer's ownership to: ", BridgeTokenFactory.address);
  const ProofConsumerContract = await ethers.getContractFactory("ProofConsumer");
  const proofConsumer = ProofConsumerContract.attach(PROOF_CONSUMER_ADDRESS);
  await proofConsumer.transferOwnership(BridgeTokenFactory.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
