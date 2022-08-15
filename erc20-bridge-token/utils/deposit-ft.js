const { ethers } = require("hardhat");
const { nearAPI, borshifyOutcomeProof } = require("rainbow-bridge-utils");
const os = require("os");
const path = require("path");

function keyStorePath() {
    return path.join(os.homedir(), '.near-credentials');
}

async function deposit({ nearAccountId, ethTokenFactoryAddress, nearOnEthClientAddress, txReceiptId, receiverId, nearNodeUrl, nearNetworkId }) {
    const keyStore = new nearAPI.keyStores.UnencryptedFileSystemKeyStore(keyStorePath())
    const near = await nearAPI.connect({
        nodeUrl: nearNodeUrl,
        networkId: nearNetworkId,
        masterAccount: nearAccountId,
        deps: { keyStore: keyStore }
    });

    const nearOnEthClientAbi = [
        "function bridgeState() view returns (tuple(uint currentHeight, uint nextTimestamp, uint nextValidAt, uint numBlockProducers))",
    ];
    const clientContract = new ethers.Contract(nearOnEthClientAddress, nearOnEthClientAbi, ethers.provider);
    const clientState = await clientContract.bridgeState();
    const proofBlockHeight = clientState.currentHeight.toNumber();
    const proof = await getProof({ near, txReceiptId, receiverId, proofBlockHeight });
    const borshProof = borshifyOutcomeProof(proof);
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(ethTokenFactoryAddress);
    await BridgeTokenFactory.deposit(borshProof, proofBlockHeight);
}

async function getProof({
    near,
    txReceiptId,
    receiverId,
    proofBlockHeight,
}) {
    const proofBlock = await near.connection.provider.block({
        blockId: proofBlockHeight,
    });
    const proofBlockHash = proofBlock.header.hash;
    try {
        const proof = await near.connection.provider.sendJsonRpc(
            'light_client_proof',
            {
                type: 'receipt',
                receipt_id: txReceiptId,
                receiver_id: receiverId,
                light_client_head: proofBlockHash
            }
        );

        return proof;
    } catch (txRevertMessage) {
        console.log('Failed to get proof.');
        console.log(txRevertMessage.toString());
    }
}

exports.deposit = deposit;
exports.getProof = getProof;