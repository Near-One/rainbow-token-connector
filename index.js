const fs = require('fs');

const rainbowLib = require('rainbow-bridge-lib');
const utils = rainbowLib.utils;
const nearAPI = rainbowLib.nearAPI;

const NEAR_CONNECTOR_DEPOSIT = nearAPI.utils.format.parseNearAmount('50');
const NEAR_CONNECTOR_NEW_GAS = '100000000000000';
const ETH_CONNECTOR_DEPLOY_GAS = 5000000;
const ETH_BRIDGE_TOKEN_DEPLOY_GAS = 5000000;
const NEAR_BRIDGE_TOKEN_DEPOSIT = nearAPI.utils.format.parseNearAmount('40');
const NEAR_BRIDGE_TOKEN_DEPLOY_GAS = '100000000000000';

async function createNearConnector(masterAccount, config) {
    if (!await rainbowLib.utils.accountExists(masterAccount.connection, config.nearConnectorId)) {
        const code = fs.readFileSync('res/bridge_token_factory.wasm');
        const newArgs = {
            prover_account: config.nearEthProverId,
            locker_address: utils.remove0x(config.ethConnectorAddress),
        };
        await masterAccount.signAndSendTransaction(config.nearConnectorId, [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(NEAR_CONNECTOR_DEPOSIT),
            nearAPI.transactions.deployContract(code),
            nearAPI.transactions.functionCall('new', newArgs, NEAR_CONNECTOR_NEW_GAS)
        ]);
    }
    return new nearAPI.Contract(masterAccount, config.nearConnectorId, {
        viewMethods: ['get_bridge_token_account_id'],
        changeMethods: ['deposit', 'deploy_bridge_token', 'lock', 'unlock'],
    });
}

async function createEthConnector(web3, config) {
    contract = utils.getEthContract(web3, 'res/BridgeTokenFactory', config.ethConnectorAddress);
    if (!config.ethConnectorAddress) {
        console.log(`Deploy ETH connector(${config.nearConnectorId}, ${config.ethProverAddress})`);
        contract = await contract.deploy({
            data: `0x${contract.bin}`,
            arguments: [Buffer.from(config.nearConnectorId, 'utf8'), config.ethProverAddress]
        }).send({
            gas: ETH_CONNECTOR_DEPLOY_GAS,
        });
        config.ethConnectorAddress = contract.options.address;
    }
    return contract;
}

/**
 * Creates a Contract object for BridgeToken for given address.
 * If it doesn't exist, deploys a new one (costs $NEAR).
 * @param {nearAPI.Contract} nearConnector Connector Contract
 * @param {address} tokenAddress address of Ethereum token
 */
async function createNearBridgeToken(nearConnector, tokenAddress) {
    tokenAddress = utils.remove0x(tokenAddress);
    let bridgeTokenId;
    try {
        bridgeTokenId = await nearConnector.get_bridge_token_account_id({ 'address': tokenAddress });
    } catch (error) {
        if (!error.message.includes('BridgeToken with such address does not exist')) {
            throw error;
        }
        await nearConnector.deploy_bridge_token(
            { 'address': tokenAddress },
            NEAR_BRIDGE_TOKEN_DEPLOY_GAS, NEAR_BRIDGE_TOKEN_DEPOSIT);
        bridgeTokenId = await nearConnector.get_bridge_token_account_id({ 'address': tokenAddress });
    }    
    return new nearAPI.Contract(nearConnector.masterAccount, bridgeTokenId, {
        viewMethods: ['get_balance', 'get_total_supply'],
        changeMethods: ['withdraw', 'transfer', 'transferFrom', 'inc_allowance', 'dec_allowance'],
    }); 
}

async function createEthBridgeToken(web3, ethConnector, tokenId) {
    let address;
    try {
        address = await ethConnector.methods.nearToEthToken(tokenId).call();
    } catch (error) {
        if (!error.message.includes('ERR_NOT_BRIDGE_TOKEN')) {
            throw error;
        }
        address = await ethConnector.methods.newBridgeToken(tokenId).call();
        await ethConnector.methods.newBridgeToken(tokenId).send({
            gas: ETH_BRIDGE_TOKEN_DEPLOY_GAS,
        });
    }
    return utils.getEthContract(web3, 'res/BridgeToken', address);
}

module.exports = {
    createNearConnector,
    createEthConnector,
    createNearBridgeToken,
    createEthBridgeToken,
}