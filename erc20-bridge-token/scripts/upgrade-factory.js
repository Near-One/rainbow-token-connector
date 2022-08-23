require('dotenv').config();
const { ethers, upgrades } = require("hardhat");

const PROXY_ADDRESS = process.env.BRIDGE_TOKEN_FACTORY_PROXY_ADDRESS;


async function main() {
    const [signerAccount] = await ethers.getSigners();
    console.log("Upgrading contracts with the account:", signerAccount.address);
    console.log("Account balance:", (await signerAccount.getBalance()).toString());

    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    console.log("Current implementation address:", await upgrades.erc1967.getImplementationAddress(PROXY_ADDRESS));
    console.log("Upgrade factory, proxy address", PROXY_ADDRESS);
    await upgrades.upgradeProxy(PROXY_ADDRESS, BridgeTokenFactoryContract);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });