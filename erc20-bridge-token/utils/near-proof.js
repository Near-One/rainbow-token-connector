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

exports.getProof = getProof;
