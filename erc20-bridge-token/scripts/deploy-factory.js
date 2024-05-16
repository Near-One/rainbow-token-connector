require("dotenv").config();
const { ethers, upgrades } = require("hardhat");

const BRIDGE_TOKEN_IMPL_ADDRESS = process.env.BRIDGE_TOKEN_IMPL_ADDRESS;
const NEAR_TOKEN_LOCKER = Buffer.from(process.env.NEAR_TOKEN_LOCKER, "utf-8");
const PROVER_ADDRESS = process.env.PROVER_ADDRESS;
const MIN_BLOCK_ACCEPTANCE_HEIGHT = parseInt(
  process.env.MIN_BLOCK_ACCEPTANCE_HEIGHT,
);

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);
  const accountBalance = await deployer.provider.getBalance(deployer.address);
  console.log("Account balance:", accountBalance.toString());
  console.log("Bridge token impl address: ", BRIDGE_TOKEN_IMPL_ADDRESS);
  console.log("Prover address:", PROVER_ADDRESS);
  console.log("Near token locker:", NEAR_TOKEN_LOCKER.toString());
  console.log("Min block acceptance height:", MIN_BLOCK_ACCEPTANCE_HEIGHT);

  const BridgeTokenFactoryContract =
    await ethers.getContractFactory("BridgeTokenFactory");
  const BridgeTokenFactory = await upgrades.deployProxy(
    BridgeTokenFactoryContract,
    [
      BRIDGE_TOKEN_IMPL_ADDRESS,
      NEAR_TOKEN_LOCKER,
      PROVER_ADDRESS,
      MIN_BLOCK_ACCEPTANCE_HEIGHT,
    ],
    {
      initializer: "initialize",
      timeout: 0,
    },
  );
  await BridgeTokenFactory.waitForDeployment();
  console.log(
    `BridgeTokenFactory deployed at ${await BridgeTokenFactory.getAddress()}`,
  );
  console.log(
    "Implementation address:",
    await upgrades.erc1967.getImplementationAddress(
      await BridgeTokenFactory.getAddress(),
    ),
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
