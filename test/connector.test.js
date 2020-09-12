const fs = require('fs');
const connector = require('../index.js');

const rainbowLib = require('rainbow-bridge-lib');
const utils = rainbowLib.utils;
const nearAPI = rainbowLib.nearAPI;

jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;

const NEAR_MOCK_PROVER_DEPOSIT = nearAPI.utils.format.parseNearAmount('50');
const NEAR_TTOKEN_NEW_GAS = '100000000000000';
const ETH_MOCK_PROVER_DEPLOY_GAS = 200000;
const ETH_TEST_TOKEN_DEPLOY_GAS = 1000000;

async function setupMockProvers(masterAccount, web3, config) {
    if (!await utils.accountExists(masterAccount.connection, config.nearEthProverId)) {
        const code = fs.readFileSync('res/mock_prover.wasm');
        await masterAccount.signAndSendTransaction(config.nearEthProverId, [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(NEAR_MOCK_PROVER_DEPOSIT),
            nearAPI.transactions.deployContract(code),
        ]);
    }
    let contract = utils.getEthContract(web3, 'res/NearProverMock', config.ethProverAddress);
    if (!config.ethProverAddress) {
        contract = await contract.deploy({ data: `0x${contract.bin}`, arguments: [] }).send({
            gas: ETH_MOCK_PROVER_DEPLOY_GAS,
        });
        config.ethProverAddress = contract.options.address;
    }
}

async function setupTestTokens(masterAccount, web3, config) {
    if (!await utils.accountExists(masterAccount.connection, config.nearTestTokenId)) {
        const code = fs.readFileSync('res/test_token.wasm');
        await masterAccount.signAndSendTransaction(config.nearTestTokenId, [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(NEAR_MOCK_PROVER_DEPOSIT),
            nearAPI.transactions.deployContract(code),
            nearAPI.transactions.functionCall("new", {owner_id: masterAccount.accountId, total_supply: '10000'}, NEAR_TTOKEN_NEW_GAS)
        ]);
    }
    const nearToken = new nearAPI.Contract(masterAccount, config.nearTestTokenId, {
        viewMethods: ['get_balance', 'get_total_supply'],
        changeMethods: ['approve', 'tranfer', 'tranferFrom'],
    });
    let ethToken = utils.getEthContract(web3, 'res/TToken', config.ethTestTokenAddress);
    if (!config.ethTestTokenAddress) {
        ethToken = await ethToken.deploy({ data: `0x${ethToken.bin}`, arguments: [] }).send({
            gas: ETH_TEST_TOKEN_DEPLOY_GAS,
        });
        config.ethTestTokenAddress = ethToken.options.address;
    }
    return { nearToken, ethToken };
}

const NETWORK_ID = process.env.NODE_ENV || 'test';
const config = rainbowLib.getConfig(NETWORK_ID);

describe('--- Token Connector ---', () => {
    test('deploy connector', async () => {
        const date = Date.now().toString().slice(-5);
        config.nearTestTokenId = `t${date}.test.near`;
        config.nearConnectorId = `c${date}.test.near`;
        const { near, web3 } = await utils.setupEthNear(config);
        const masterAccount = await near.account(config.masterAccount);
        await setupMockProvers(masterAccount, web3, config);
        const {nearToken, ethToken} = await setupTestTokens(masterAccount, web3, config);
        const ethConnector = await connector.createEthConnector(web3, config);
        const nearConnector = await connector.createNearConnector(masterAccount, config);

        const nearBridgeToken = await connector.createNearBridgeToken(nearConnector, config.ethTestTokenAddress);
        const ethBridgeToken = await connector.createEthBridgeToken(web3, ethConnector, config.nearTestTokenId);
    });
});
