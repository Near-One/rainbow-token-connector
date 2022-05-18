/**
 * @type import('hardhat/config').HardhatUserConfig
 */
require("@nomiclabs/hardhat-waffle");
require('@openzeppelin/hardhat-upgrades')
require('solidity-coverage')

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
            runs: 200
          }
        }
      }
    ]
  }
}
