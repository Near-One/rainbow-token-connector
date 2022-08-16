const { RobustWeb3 } = require("rainbow-bridge-utils");
const { EthProofExtractor, receiptFromWeb3, logFromWeb3 } = require("rainbow-bridge-eth2near-block-relay");
const utils = require('ethereumjs-util')

async function ethToNearFindProof({ lockedEvent, ethNodeUrl }) {
    const robustWeb3 = new RobustWeb3(ethNodeUrl);
    const web3 = robustWeb3.web3;
    const extractor = new EthProofExtractor();
    extractor.initialize(ethNodeUrl);

    const receipt = await extractor.extractReceipt(lockedEvent.transactionHash);
    const block = await extractor.extractBlock(receipt.blockNumber);
    const tree = await extractor.buildTrie(block);
    const extractedProof = await extractor.extractProof(
        web3,
        block,
        tree,
        receipt.transactionIndex
    );
    // destroy extractor here to close its web3 connection
    extractor.destroy();

    let txLogIndex = -1;
    let logFound = false;
    let log;
    for (const receiptLog of receipt.logs) {
        txLogIndex++
        const blockLogIndex = receiptLog.logIndex;
        if (blockLogIndex === lockedEvent.logIndex) {
            logFound = true;
            log = receiptLog;
            break;
        }
    }
    if (logFound) {
        const logEntryData = logFromWeb3(log).serialize();
        const receiptIndex = extractedProof.txIndex;
        const receiptData = receiptFromWeb3(receipt).serialize();
        const headerData = extractedProof.header_rlp;
        const proof = [];
        for (const node of extractedProof.receiptProof) {
            proof.push(utils.rlp.encode(node));
        }
        const proofLocker = {
            log_index: txLogIndex,
            log_entry_data: logEntryData,
            receipt_index: receiptIndex,
            receipt_data: receiptData,
            header_data: headerData,
            proof
        }
        return proofLocker;
    } else {
        console.log(`Failed to find log for event ${lockedEventRaw}`)
    }
}

exports.ethToNearFindProof = ethToNearFindProof;
