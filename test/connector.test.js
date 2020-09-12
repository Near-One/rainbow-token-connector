const fs = require('fs');
const connector = require('../index.js');

const rainbowLib = require('rainbow-bridge-lib');
const utils = rainbowLib.utils;
const nearAPI = rainbowLib.nearAPI;

const NEAR_CONNECTOR_DEPOSIT = nearAPI.utils.format.formatNearAmount('50');
const NEAR_MOCK_PROVER_DEPOSIT = nearAPI.utils.format.formatNearAmount('50');
const ETH_MOCK_PROVER_DEPLOY_GAS = 200000;
const NEAR_CONNECTOR_NEW_GAS = '100000000000';
const ETH_CONNECTOR_DEPLOY_GAS = 5000000;

async function createNEARConnector(masterAccount, config) {
    const code = fs.readFileSync('res/bridge_token_factory.wasm');
    if (!rainbowLib.utils.accountExists(masterAccount.connection, config.nearConnectorId)) {
        const newArgs = {};
        await account.signAndSendTransaction(config.nearConnectorId, [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(NEAR_CONNECTOR_DEPOSIT),
            nearAPI.transactions.deployContract(code),
            nearAPI.transactions.functionCall('new', newArgs, NEAR_CONNECTOR_NEW_GAS)
        ]);
    }
    return new nearAPI.Contract(masterAccount, config.nearConnectorId, {
        viewMethods: [],
        changeMethods: [],
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
            from: config.ethFrom,
            gas: ETH_CONNECTOR_DEPLOY_GAS,
        });
        config.ethConnectorAddress = contract.options.address;
    }
    return contract;
}

async function setupEthNear(config) {
    const keyStore = await utils.createLocalKeyStore(config.networkId, config.keyPath);
    delete config.keyPath;
    const near = await nearAPI.connect({ networkId: config.networkId, nodeUrl: config.nearNodeUrl, deps: { keyStore } });
    const web3 = await utils.getWeb3(config);
    web3.eth.defaultAccount = utils.addSecretKey(web3, config.ethFromSecretKey);
    config.ethFrom = web3.eth.defaultAccount;
    return { near, web3 }
}

async function setupMockProvers(masterAccount, web3, config) {
    const code = fs.readFileSync('res/mock_prover.wasm');
    if (!rainbowLib.utils.accountExists(masterAccount.connection, config.nearEthProverId)) {
        await masterAccount.signAndSendTransaction(config.nearEthProverId, [
            nearAPI.transactions.createAccount(),
            nearAPI.transactions.transfer(NEAR_MOCK_PROVER_DEPOSIT),
            nearAPI.transactions.deployContract(code),
        ]);
    }
    let contract = utils.getEthContract(web3, 'res/NearProverMock', config.ethProverAddress);
    if (!config.ethProverAddress) {
        contract = await contract.deploy({ data: `0x${contract.bin}`, arguments: [] }).send({
            from: config.ethFrom,
            gas: ETH_MOCK_PROVER_DEPLOY_GAS,
        });
        config.ethProverAddress = contract.options.address;
    }
}

const NETWORK_ID = process.env.NODE_ENV || 'test';
const config = rainbowLib.getConfig(NETWORK_ID);

describe('--- Token Connector ---', () => {
    test('deploy connector', async () => {
        config.nearConnectorId = 'connector.test.near';
        const { near, web3 } = await setupEthNear(config);
        const masterAccount = await near.account(config.masterAccount);
        await setupMockProvers(near, web3, config);
        const nearConnector = await createNEARConnector(masterAccount, config, 'test-connector.test.near');
        const ethConnector = await createEthConnector(web3, config);
    });
});