const { ethers, network } = require("hardhat");
const { nearAPI } = require("rainbow-bridge-utils");
const { ethToNearFindProof } = require("./eth-proof");
const { NearTokenLocker } = require("./near-locker");

const os = require("os");
const path = require("path");

function keyStorePath() {
    return path.join(os.homedir(), '.near-credentials');
}

async function withdraw({ ethTokenFactoryAddress, token, amount, recipient }) {
    const BridgeTokenFactoryContract = await ethers.getContractFactory("BridgeTokenFactory");
    const BridgeTokenFactory = BridgeTokenFactoryContract.attach(ethTokenFactoryAddress);
    const tx = await BridgeTokenFactory.withdraw(token, amount, recipient);
    const receipt = await tx.wait();
    const event = receipt.events.find(event => event.event === 'Withdraw');
    console.log("Withdraw event:", {
        transactionHash: event.transactionHash,
        logIndex: event.logIndex
    });
}

async function finishWithdraw({
    nearAccountId,
    nearTokenLockerAccountId,
    lockedEvent,
    nearNodeUrl,
    nearNetworkId
}) {
    console.log('Finish deposit for event', lockedEvent);
    const keyStore = new nearAPI.keyStores.UnencryptedFileSystemKeyStore(keyStorePath())
    const near = await nearAPI.connect({
        nodeUrl: nearNodeUrl,
        networkId: nearNetworkId,
        masterAccount: nearAccountId,
        deps: { keyStore: keyStore }
    });
    const nearAccount = new nearAPI.Account(
        near.connection,
        nearAccountId
    );

    const proof = await ethToNearFindProof({ lockedEvent, ethNodeUrl: network.config.url });
    const nearTokenLocker = new NearTokenLocker(nearAccount, nearTokenLockerAccountId);
    await nearTokenLocker.accessKeyInit();

    const res = await nearTokenLocker.withdraw(
        proof,
        '300000000000000',
        '60000000000000000000000'
    );
    console.log(res);
}


exports.withdraw = withdraw;
exports.finishWithdraw = finishWithdraw;
