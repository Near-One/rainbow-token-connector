require('dotenv').config();
const { ethers, upgrades } = require("hardhat");

const TOKEN_FACTORY_ADDRESS = process.env.TOKEN_FACTORY_ADDRESS;


async function main() {
    const [signerAccount] = await ethers.getSigners();
    console.log("Upgrading contracts with the account:", signerAccount.address);
    console.log("Account balance:", (await signerAccount.getBalance()).toString());

    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    console.log("Current implementation address:", await upgrades.erc1967.getImplementationAddress(TOKEN_FACTORY_ADDRESS));
    console.log("Upgrade factory, proxy address", TOKEN_FACTORY_ADDRESS);
    await upgrades.upgradeProxy(TOKEN_FACTORY_ADDRESS, BridgeTokenFactoryContract);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });