/**
 * @type import('hardhat/config').HardhatUserConfig
 */
require("@nomiclabs/hardhat-waffle");
require('hardhat-contract-sizer');
require('@openzeppelin/hardhat-upgrades')
require('solidity-coverage')

require('dotenv').config();

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const ETH_PRIVATE_KEY = process.env.ETH_PRIVATE_KEY;
const NEAR_RPC_URL = process.env.NEAR_RPC_URL;
const NEAR_NETWORK = process.env.NEAR_NETWORK;
const NEAR_TOKEN_LOCKER = process.env.NEAR_TOKEN_LOCKER;
const NEAR_ON_ETH_CLIENT_ADDRESS = process.env.NEAR_ON_ETH_CLIENT_ADDRESS;

task('deposit-ft', 'Deposit near tokens on the eth side')
  .addParam('nearAccount', 'Near account id to get the proof')
  .addParam('factory', 'The address of the eth factory contract')
  .addParam('txReceiptId', 'Receipt id of the lock event on Near side')
  .setAction(async (taskArgs, hre) => {
    const { deposit } = require('./utils/deposit-ft.js');
    await deposit({
      nearAccountId: taskArgs.nearAccount,
      ethTokenFactoryAddress: taskArgs.factory,
      nearOnEthClientAddress: NEAR_ON_ETH_CLIENT_ADDRESS,
      txReceiptId: taskArgs.txReceiptId,
      receiverId: NEAR_TOKEN_LOCKER,
      nearNodeUrl: NEAR_RPC_URL,
      nearNetworkId: NEAR_NETWORK,
    })
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
