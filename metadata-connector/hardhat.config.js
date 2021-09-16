require("@nomiclabs/hardhat-waffle");
require('dotenv').config();

const AURORA_PRIVATE_KEY = process.env.AURORA_PRIVATE_KEY;

module.exports = {
  solidity: "0.8.5"
};
