const hre = require("hardhat");

async function main() {
  const ERC20MetadataLogger = await hre.ethers.getContractFactory("ERC20MetadataLogger");
  const erc20MetadataLogger = await ERC20MetadataLogger.deploy();
  await erc20MetadataLogger.deployed();
  console.log("ERC20MetadataLogger deployed to:", erc20MetadataLogger.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
