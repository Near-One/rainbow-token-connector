const { ethers } = require("hardhat");
const { nearAPI, borshifyOutcomeProof } = require("rainbow-bridge-utils");
const os = require("os");
const path = require("path");

function keyStorePath() {
    return path.join(os.homedir(), '.near-credentials');
}

async function deposit({ nearAccountId, ethTokenFactoryAddress, txReceiptId, receiverId, nearNodeUrl, nearNetworkId }) {
    const keyStore = new nearAPI.keyStores.UnencryptedFileSystemKeyStore(keyStorePath())
    const near = await nearAPI.connect({
        nodeUrl: nearNodeUrl,
        networkId: nearNetworkId,
        masterAccount: nearAccountId,
        deps: { keyStore: keyStore }
    });

    const proof = await getProof({ near, txReceiptId, nearAccountId });
    const borshProof = borshifyOutcomeProof(proof.proofData);
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(ethTokenFactoryAddress);
    const res = await BridgeTokenFactory.deposit(borshProof, proof.proofBlockHeight);
    console.log(res);
}

async function getProof({
    near,
    txReceiptId,
    nearAccountId
}) {
    const status = await near.connection.provider.status();
    const headBlock = await near.connection.provider.block({
        blockId: status.sync_info.latest_block_height
    });
    const proofBlockHeight = headBlock.header.height;
    const headBlockHash = headBlock.header.last_final_block;

    try {
        let proofData = await near.connection.provider.sendJsonRpc(
            'light_client_proof',
            {
                type: 'receipt',
                receipt_id: txReceiptId,
                receiver_id: nearAccountId,
                light_client_head: headBlockHash
            }
        )

        return { proofData, proofBlockHeight }
    } catch (txRevertMessage) {
        console.log('Failed to get proof.')
        console.log(txRevertMessage.toString())
    }
}

exports.deposit = deposit;
exports.getProof = getProof;