require('dotenv').config();
const { ethers, upgrades } = require("hardhat");

const TOKEN_FACTORY_ADDRESS = process.env.TOKEN_FACTORY_ADDRESS;

async function main() {
    const [signerAccount] = await ethers.getSigners();
    console.log("Upgrading contracts with the account:", signerAccount.address);
    console.log("Account balance:", (await signerAccount.getBalance()).toString());

    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const implAddress = await upgrades.erc1967.getImplementationAddress(TOKEN_FACTORY_ADDRESS);
    console.log("Token factory proxy address:", TOKEN_FACTORY_ADDRESS);
    console.log("Current implementation address:", implAddress);
    console.log("Proxy admin:", await ethers.provider.getStorageAt(
      TOKEN_FACTORY_ADDRESS,
      "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
    );
    await upgrades.validateUpgrade(implAddress, BridgeTokenFactoryContract, {
      kind: "transparent"
    });
    const newImplAddress = await upgrades.deployImplementation(BridgeTokenFactoryContract);
    console.log("New implementation address", newImplAddress);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });