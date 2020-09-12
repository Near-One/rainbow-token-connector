const fs = require('fs');

const rainbowLib = require('rainbow-bridge-lib');
const { BorshContract } = require('rainbow-bridge-lib/rainbow/borsh');
const {
    EthProofExtractor,
    receiptFromWeb3,
    logFromWeb3,
} = require('rainbow-bridge-lib/eth-proof-extractor');
const { rlp } = require('ethereumjs-util')

const utils = rainbowLib.utils;
const nearAPI = rainbowLib.nearAPI;

const NEAR_CONNECTOR_DEPOSIT = nearAPI.utils.format.parseNearAmount('50');
const NEAR_CONNECTOR_NEW_GAS = '100000000000000';
const ETH_CONNECTOR_DEPLOY_GAS = 5000000;
const ETH_BRIDGE_TOKEN_DEPLOY_GAS = 5000000;
const NEAR_BRIDGE_TOKEN_DEPOSIT = nearAPI.utils.format.parseNearAmount('40');
const NEAR_BRIDGE_TOKEN_DEPLOY_GAS = '100000000000000';

const NEAR_CONNECTOR_SCHEMA = {
    bool: {
        kind: 'function',
        // @ts-ignore
        ser: (b) => Buffer.from(Web3.utils.hexToBytes(b ? '0x01' : '0x00')),
        deser: (z) => readerToHex(1)(z) === '0x01',
    },
    Proof: {
        kind: 'struct',
        fields: [
            ['log_index', 'u64'],
            ['log_entry_data', ['u8']],
            ['receipt_index', 'u64'],
            ['receipt_data', ['u8']],
            ['header_data', ['u8']],
            ['proof', [['u8']]],
        ],
    },
}

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
    return new BorshContract(NEAR_CONNECTOR_SCHEMA, masterAccount, config.nearConnectorId, {
        viewMethods: ['get_bridge_token_account_id'],
        changeMethods: [
            { methodName: 'deposit', inputFieldType: 'Proof', outputFieldType: null },
            // {'deploy_bridge_token'}, 
            // {'lock'}, 
            // {'unlock'}],
        ]
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

/**
 * TODO: MOVE TO rainbow-lib
 * @param {*} web3 
 * @param {*} lockedEvent 
 */
async function ethExtractEventProof(web3, lockedEvent) {
    const extractor = EthProofExtractor.fromWeb3(web3);
    const receipt = await extractor.extractReceipt(lockedEvent.transactionHash)
    const block = await extractor.extractBlock(receipt.blockNumber)
    const tree = await extractor.buildTrie(block)
    const proof = await extractor.extractProof(
        web3,
        block,
        tree,
        receipt.transactionIndex
    )
    let txLogIndex = -1

    let logFound = false
    let log
    for (let receiptLog of receipt.logs) {
        txLogIndex++
        const blockLogIndex = receiptLog.logIndex
        if (blockLogIndex === lockedEvent.logIndex) {
            logFound = true
            log = receiptLog
            break
        }
    }

    if (!logFound) {
        throw new Error(`Log for ${lockedEvent} is not found.`);
    }

    const _proof = []
    for (const node of proof.receiptProof) {
        _proof.push(rlp.encode(node));
    }

    return {
        log_index: txLogIndex,
        log_entry_data: logFromWeb3(log).serialize(),
        receipt_index: proof.txIndex,
        receipt_data: receiptFromWeb3(receipt).serialize(),
        header_data: proof.header_rlp,
        proof: _proof
    };
}

module.exports = {
    createNearConnector,
    createEthConnector,
    createNearBridgeToken,
    createEthBridgeToken,
    ethExtractEventProof,
}
