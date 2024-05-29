require("dotenv").config();
require("@openzeppelin/hardhat-upgrades");
require("@nomicfoundation/hardhat-verify");
require("@nomicfoundation/hardhat-chai-matchers");

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const INFURA_API_KEY = process.env.INFURA_API_KEY;
const ETH_PRIVATE_KEY = process.env.ETH_PRIVATE_KEY || '11'.repeat(32);
const NEAR_RPC_URL = process.env.NEAR_RPC_URL;
const NEAR_NETWORK = process.env.NEAR_NETWORK;
const NEAR_TOKEN_LOCKER = process.env.NEAR_TOKEN_LOCKER;
const NEAR_ON_ETH_CLIENT_ADDRESS = process.env.NEAR_ON_ETH_CLIENT_ADDRESS;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;

task('finish-deposit-ft', 'Deposit NEP-141 tokens on the Ethereum side')
  .addParam('nearAccount', 'Near account id to get the proof')
  .addParam('factory', 'The address of the eth factory contract')
  .addParam('txReceiptId', 'Receipt id of the lock event on Near side')
  .setAction(async (taskArgs) => {
    const { findProof } = require('./utils/near-proof.js');
    const proof = await findProof({
      nearAccountId: taskArgs.nearAccount,
      nearOnEthClientAddress: NEAR_ON_ETH_CLIENT_ADDRESS,
      txReceiptId: taskArgs.txReceiptId,
      receiverId: NEAR_TOKEN_LOCKER,
      nearNodeUrl: NEAR_RPC_URL,
      nearNetworkId: NEAR_NETWORK,
    });

    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(taskArgs.factory);
    await BridgeTokenFactory.deposit(proof.borshProof, proof.proofBlockHeight);
  });

task('set-metadata-ft', 'Set metadata for NEP-141 tokens on the Ethereum side')
  .addParam('nearAccount', 'Near account id to get the proof')
  .addParam('factory', 'The address of the eth factory contract')
  .addParam('txReceiptId', 'Receipt id of the lock event on Near side')
  .setAction(async (taskArgs) => {
    const { findProof } = require('./utils/near-proof.js');
    const proof = await findProof({
      nearAccountId: taskArgs.nearAccount,
      nearOnEthClientAddress: NEAR_ON_ETH_CLIENT_ADDRESS,
      txReceiptId: taskArgs.txReceiptId,
      receiverId: NEAR_TOKEN_LOCKER,
      nearNodeUrl: NEAR_RPC_URL,
      nearNetworkId: NEAR_NETWORK,
    });

    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(taskArgs.factory);
    await BridgeTokenFactory.setMetadata(proof.borshProof, proof.proofBlockHeight);
  });

task('new-token', 'Deploy new bridge token')
  .addParam('nearTokenAccount', 'Near account id of the token')
  .addParam('factory', 'The address of the eth factory contract')
  .setAction(async (taskArgs) => {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(taskArgs.factory);

    console.log("Deploy new bridge token:", taskArgs.nearTokenAccount);
    let tx = await BridgeTokenFactory.newBridgeToken(taskArgs.nearTokenAccount);
    await tx.wait(5);
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(taskArgs.nearTokenAccount);
    console.log(`Token deployed at ${tokenProxyAddress}`);
  });

task('add-token-to-whitelist-eth', 'Add a token to whitelist')
  .addParam('nearTokenAccount', 'Near account id of the token')
  .addParam('factory', 'The address of the eth factory contract')
  .addParam('mode', 'Whitelist mode: [ NotInitialized, Blocked, CheckToken, CheckAccountAndToken ]')
  .setAction(async (taskArgs) => {
    const WhitelistMode = {
      NotInitialized: 0,
      Blocked: 1,
      CheckToken: 2,
      CheckAccountAndToken: 3
    }
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(taskArgs.factory);
    const tx = await BridgeTokenFactory.setTokenWhitelistMode(taskArgs.nearTokenAccount, WhitelistMode[taskArgs.mode]);
    const receipt = await tx.wait();
    console.log("Tx hash", receipt.transactionHash);
  });

task('add-account-to-whitelist-eth', 'Add an account to whitelist')
  .addParam('nearTokenAccount', 'Near account id of the token')
  .addParam('ethAccount', 'Ethereum account address to add to whitelist')
  .addParam('factory', 'The address of the factory contract on Ethereum')
  .setAction(async (taskArgs) => {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(taskArgs.factory);
    const tx = await BridgeTokenFactory.addAccountToWhitelist(taskArgs.nearTokenAccount, taskArgs.ethAccount);
    const receipt = await tx.wait();
    console.log("Tx hash", receipt.transactionHash);
  });

task('withdraw-ft', 'Withdraw bridged tokens from the Ethereum side')
  .addParam('factory', 'The address of the eth factory contract')
  .addParam('token', 'Near token account id')
  .addParam('bridgeTokenProxy', 'Bridged token address on eth')
  .addParam('amount', 'Amount of tokens to withdraw')
  .addParam('recipient', 'Near recipient account id ')
  .setAction(async (taskArgs) => {
    const { withdraw } = require('./utils/withdraw-ft.js');
    await withdraw({
      ethTokenFactoryAddress: taskArgs.factory,
      token: taskArgs.token,
      amount: taskArgs.amount,
      recipient: taskArgs.recipient
    });
  });

task('finish-withdraw-ft', 'Finish withdraw on near side')
  .addParam('nearAccount', 'Near account id to submit the proof')
  .addParam('locker', 'The address of the near locker contract')
  .addParam('event', 'Lock event in json format {"transactionHash":"0x00", "logIndex":0}')
  .setAction(async (taskArgs) => {
    const { finishWithdraw } = require('./utils/withdraw-ft.js');
    await finishWithdraw({
      nearAccountId: taskArgs.nearAccount,
      nearTokenLockerAccountId: taskArgs.locker,
      lockedEvent: JSON.parse(taskArgs.event),
      nearNodeUrl: NEAR_RPC_URL,
      nearNetworkId: NEAR_NETWORK,
    });
  });

task('etherscan-verify', 'Verify contract on etherscan')
  .addParam('address', 'Contract address')
  .addParam('args', 'Constructor arguments in JSON array')
  .setAction(async (taskArgs, hre) => {
    await hre.run("verify:verify", {
      address: taskArgs.address,
      constructorArguments: JSON.parse(taskArgs.args),
    });
  });

module.exports = {
  paths: {
    sources: './contracts',
    artifacts: './build'
  },
  solidity: {
    compilers: [
      {
        version: '0.8.24',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          },
          metadata: {
            // do not include the metadata hash, since this is machine dependent
            // and we want all generated code to be deterministic
            // https://docs.soliditylang.org/en/v0.8.24/metadata.html
            bytecodeHash: "none"
          }
        }
      }
    ]
  },
  networks: {
    sepolia: {
      url: INFURA_API_KEY
        ? `https://sepolia.infura.io/v3/${INFURA_API_KEY}`
        : `https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY}`,
      accounts: [`${ETH_PRIVATE_KEY}`]
    },
    mainnet: {
      url: INFURA_API_KEY
        ? `https://mainnet.infura.io/v3/${INFURA_API_KEY}`
        : `https://eth-mainnet.alchemyapi.io/v2/${ALCHEMY_API_KEY}`,
      accounts: [`${ETH_PRIVATE_KEY}`]
    },
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY
  },
}
