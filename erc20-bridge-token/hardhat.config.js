/**
 * @type import('hardhat/config').HardhatUserConfig
 */
require("@nomiclabs/hardhat-waffle");
require('hardhat-contract-sizer');
require('@openzeppelin/hardhat-upgrades')
require('solidity-coverage')

require('dotenv').config();

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const ETH_PRIVATE_KEY = process.env.ETH_PRIVATE_KEY || '11'.repeat(32);
const NEAR_RPC_URL = process.env.NEAR_RPC_URL;
const NEAR_NETWORK = process.env.NEAR_NETWORK;
const NEAR_TOKEN_LOCKER = process.env.NEAR_TOKEN_LOCKER;
const NEAR_ON_ETH_CLIENT_ADDRESS = process.env.NEAR_ON_ETH_CLIENT_ADDRESS;

task('finish-deposit-ft', 'Deposit near tokens on the eth side')
  .addParam('nearAccount', 'Near account id to get the proof')
  .addParam('factory', 'The address of the eth factory contract')
  .addParam('txReceiptId', 'Receipt id of the lock event on Near side')
  .setAction(async (taskArgs) => {
    const { finishDeposit } = require('./utils/deposit-ft.js');
    await finishDeposit({
      nearAccountId: taskArgs.nearAccount,
      ethTokenFactoryAddress: taskArgs.factory,
      nearOnEthClientAddress: NEAR_ON_ETH_CLIENT_ADDRESS,
      txReceiptId: taskArgs.txReceiptId,
      receiverId: NEAR_TOKEN_LOCKER,
      nearNodeUrl: NEAR_RPC_URL,
      nearNetworkId: NEAR_NETWORK,
    })
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
    await BridgeTokenFactoryContract.setTokenWhitelistMode(tokenProxyAddress, 2);
  });

task('withdraw-ft', 'Withdraw bridged tokens on the eth side')
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

module.exports = {
  paths: {
    sources: './contracts',
    artifacts: './build'
  },
  solidity: {
    compilers: [
      {
        version: '0.8.11',
        settings: {
          optimizer: {
            enabled: true,
            runs: 1
          }
        }
      }
    ]
  },
  networks: {
    goerli: {
      url: `https://eth-goerli.alchemyapi.io/v2/${ALCHEMY_API_KEY}`,
      accounts: [`${ETH_PRIVATE_KEY}`]
    }
  }
}
