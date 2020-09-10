const bs58 = require('bs58');
const truffleAssert = require('truffle-assertions');

const { serialize } = require('rainbow-bridge-lib/rainbow/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/rainbow/borshify-proof.js');

const BridgeTokenFactory = artifacts.require('BridgeTokenFactory');
const BridgeToken = artifacts.require('BridgeToken');
const NearProverMock = artifacts.require('test/NearProverMock');
const TToken = artifacts.require('test/TToken');

const { toWei, fromWei, hexToBytes } = web3.utils;

const SCHEMA = {
    'Deposit': {
        kind: 'struct', fields: [
            ['token', 'string'],
            ['amount', 'u128'],
            ['recipient', [20]],
        ]
    },
    'Unlock': {
        kind: 'struct', fields: [
            ['amount', 'u128'],
            ['token', [20]],
            ['recipient', [20]],
        ]
    }
};

contract('TokenLocker', function ([_, addr1]) {
    beforeEach(async function () {
        this.token = await TToken.new();
        this.prover = await NearProverMock.new();
        this.locker = await BridgeTokenFactory.new(Buffer.from('nearfuntoken', 'utf-8'), this.prover.address);
        await this.token.mint(this.locker.address, toWei('100'));
        await this.token.mint(addr1, toWei('2'));
    });

    it('lock to NEAR', async function() {
        const preBalance1 = await this.token.balanceOf(addr1);
        expect(fromWei(preBalance1)).equal('2');
        await this.token.approve(this.locker.address, toWei('1'), { from: addr1 });
        const tx = await this.locker.lockToken(this.token.address, toWei('1'), 'receiver', { from: addr1 });
        const afterBalance1 = await this.token.balanceOf(addr1);
        expect(fromWei(afterBalance1)).equal('1');
        truffleAssert.eventEmitted(tx, 'Locked', (event) => {
            return event.token == this.token.address && event.sender == addr1 && fromWei(event.amount) == 1 && event.accountId == 'receiver';
        });
    });

    it('deposit to Eth', async function() {
        const nearToken = 'neartoken';
        BTOKEN = await this.locker.newBridgeToken.call(nearToken);
        await this.locker.newBridgeToken('neartoken');
        btoken = await BridgeToken.at(BTOKEN);
        assert(await this.locker.isBridgeToken(btoken.address));
        expect(await this.locker.ethToNearToken(btoken.address)).equal(nearToken);
        expect(await this.locker.nearToEthToken(nearToken)).equal(btoken.address);

        const beforeBalance = await btoken.balanceOf(addr1);
        expect(fromWei(beforeBalance)).equal('0');

        let proof = require('./proof_template.json');
        proof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'Deposit', { 
            amount: toWei('1'), 
            recipient: hexToBytes(addr1), 
            token: nearToken 
        }).toString('base64');
        const tx = await this.locker.deposit(borshifyOutcomeProof(proof), 1099);
        truffleAssert.eventEmitted(tx, 'Deposit', (event) => {
            return event.recipient == addr1 && fromWei(event.amount) == 1;
        });
        const afterBalance = await btoken.balanceOf(addr1);
        expect(fromWei(afterBalance)).equal('1');
    });

    it('unlock Token', async function () {
        let proof = require('./proof_template.json');
        proof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'Unlock', {
            amount: toWei('1'),
            token: hexToBytes(this.token.address),
            recipient: hexToBytes(addr1), 
        }).toString('base64');
        const lockerBalance = await this.token.balanceOf(this.locker.address);
        const receiverBalance = await this.token.balanceOf(addr1);

        await this.locker.unlockToken(borshifyOutcomeProof(proof), 1099);

        const newLockerBalance = await this.token.balanceOf(this.locker.address);
        expect(fromWei(lockerBalance) - fromWei(newLockerBalance)).equal(1);
        const newReceiverBalance = await this.token.balanceOf(addr1);
        expect(fromWei(newReceiverBalance) - fromWei(receiverBalance)).equal(1);
    });
});
