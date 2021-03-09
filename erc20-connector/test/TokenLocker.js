const truffleAssert = require('truffle-assertions');
const BN = require("bn.js");

const { expectRevert } = require('@openzeppelin/test-helpers');
const { serialize } = require('rainbow-bridge-lib/rainbow/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/rainbow/borshify-proof.js');

const ERC20Locker = artifacts.require('ERC20Locker');
const NearProverMock = artifacts.require('test/NearProverMock');
const TToken = artifacts.require('test/TToken');

const { toWei, fromWei, hexToBytes } = web3.utils;

const SCHEMA = {
    'Unlock': {
        kind: 'struct', fields: [
            ['flag', 'u8'],
            ['amount', 'u128'],
            ['token', [20]],
            ['recipient', [20]],
        ]
    }
};

const UNPAUSED_ALL = 0;
const PAUSED_LOCK = 1 << 0;
const PAUSED_UNLOCK = 1 << 1;

contract('TokenLocker', function ([addr, addr1, addr2]) {
    const initialBalanceAddr1 = toWei('5');
    let token;
    let prover;
    let locker;

    beforeEach(async function () {
        let minBlockAcceptanceHeight = 0;
        token = await TToken.new();
        prover = await NearProverMock.new();
        locker = await ERC20Locker.new(Buffer.from('nearfuntoken', 'utf-8'), prover.address, minBlockAcceptanceHeight, addr, UNPAUSED_ALL);
        await token.mint(locker.address, toWei('100'));
        await token.mint(addr1, toWei('5'));
    });

    it('lock to NEAR', async function () {
        const preBalance1 = await token.balanceOf(addr1);
        expect(fromWei(preBalance1)).equal('5');
        await token.approve(locker.address, toWei('1'), { from: addr1 });
        const tx = await locker.lockToken(token.address, toWei('1'), 'receiver', { from: addr1 });
        const afterBalance1 = await token.balanceOf(addr1);
        expect(fromWei(afterBalance1)).equal('4');
        truffleAssert.eventEmitted(tx, 'Locked', (event) => {
            return event.token == token.address && event.sender == addr1 && fromWei(event.amount) == 1 && event.accountId == 'receiver';
        });
    });

    it('unlock from NEAR', async function () {
        let proof = require('./proof_template.json');
        proof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'Unlock', {
            flag: 0,
            amount: toWei('1'),
            token: hexToBytes(token.address),
            recipient: hexToBytes(addr1),
        }).toString('base64');
        const lockerBalance = await token.balanceOf(locker.address);
        const receiverBalance = await token.balanceOf(addr1);

        await locker.unlockToken(borshifyOutcomeProof(proof), 1099);

        const newLockerBalance = await token.balanceOf(locker.address);
        expect(fromWei(lockerBalance) - fromWei(newLockerBalance)).equal(1);
        const newReceiverBalance = await token.balanceOf(addr1);
        expect(fromWei(newReceiverBalance) - fromWei(receiverBalance)).equal(1);
    });

    it('should not exceed max token limit', async function () {
        // Mint more than 2^128 tokens
        let extraMint = (new BN(2)).pow(new BN(129));
        await token.mint(addr2, extraMint);

        const preBalance1 = await token.balanceOf(addr2);
        expect(preBalance1.sub(extraMint).toNumber()).to.be.equal(0);

        await token.approve(locker.address, extraMint, { from: addr2 });

        // Check small transactions can be done
        for (let i = 10; i <= 30; i += 10) {
            await locker.lockToken(token.address, new BN(i), 'receiver', { from: addr2 });
        }

        let totalLocked = await token.balanceOf(locker.address);

        // Check remaining tokens can't be locked
        await expectRevert(locker.lockToken(token.address, extraMint.sub(new BN(totalLocked)), 'receiver', { from: addr2 }), 'Maximum tokens locked exceeded (< 2^128 - 1)')

        let maxAllowed = (new BN(2)).pow(new BN(128)).sub(new BN(1));

        // Check number of locked tokens can't reach 2^128
        await expectRevert(locker.lockToken(token.address, maxAllowed.add(new BN(1)).sub(new BN(totalLocked)), 'receiver', { from: addr2 }), 'Maximum tokens locked exceeded (< 2^128 - 1)')

        // Check number of locked tokens can reach 2^128 - 1
        await locker.lockToken(token.address, maxAllowed.sub(totalLocked), 'receiver', { from: addr2 });
    });

    describe('Pausability', () => {
        it('Lock method', async function () {
            const amountToTransfer = toWei('1');

            // Let's try to lock some tokens
            // The balance should be changed and the `Locked` event emitted
            const preBalance1 = await token.balanceOf(addr1);
            expect(fromWei(preBalance1)).equal(fromWei(initialBalanceAddr1));
            await token.approve(locker.address, amountToTransfer, { from: addr1 });
            const tx1 = await locker.lockToken(token.address, amountToTransfer, 'receiver', { from: addr1 });
            const afterBalance1 = await token.balanceOf(addr1);
            expect(fromWei(afterBalance1)).equal((fromWei(initialBalanceAddr1) - fromWei(amountToTransfer)).toString());
            truffleAssert.eventEmitted(tx1, 'Locked', (event) => {
                return event.token == token.address
                    && event.sender == addr1
                    && fromWei(event.amount) == fromWei(amountToTransfer)
                    && event.accountId == 'receiver';
            });

            // Let's pause the Lock method
            await locker.adminPause(PAUSED_LOCK, { from: addr });

            // Let's try to lock some tokens while the lock is paused.
            // The balance shouldn't be changed and the revert should occur
            await token.approve(locker.address, amountToTransfer, { from: addr1 });
            await expectRevert.unspecified(locker.lockToken(token.address, amountToTransfer, 'receiver', { from: addr1 }));
            const afterBalance2 = await token.balanceOf(addr1);
            expect(fromWei(afterBalance2)).equal(fromWei(afterBalance1));

            // Let's unpause the Lock method
            await locker.adminPause(UNPAUSED_ALL, { from: addr });

            // Let's try to lock some tokens one more time after unpausing.
            // This should work again - the balance should be changed and the `Locked` event emitted
            await token.approve(locker.address, amountToTransfer, { from: addr1 });
            const tx3 = await locker.lockToken(token.address, amountToTransfer, 'receiver', { from: addr1 });
            const afterBalance3 = await token.balanceOf(addr1);
            expect(fromWei(afterBalance3)).equal((fromWei(afterBalance2) - fromWei(amountToTransfer)).toString());
            truffleAssert.eventEmitted(tx3, 'Locked', (event) => {
                return event.token == token.address
                    && event.sender == addr1
                    && fromWei(event.amount) == fromWei(amountToTransfer)
                    && event.accountId == 'receiver';
            });
        });

        it('Unlock method', async function () {
            const amountToUnlock = toWei('1');
            const proofBlockHeight = 1099;
            let proof = require('./proof_template.json');
            proof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'Unlock', {
                flag: 0,
                amount: amountToUnlock,
                token: hexToBytes(token.address),
                recipient: hexToBytes(addr1),
            }).toString('base64');

            // Let's try to unlock
            // The balance should be changed and the `Unlocked` event emitted
            const lockerPreBalance1 = await token.balanceOf(locker.address);
            const receiverPreBalance1 = await token.balanceOf(addr1);

            const tx1 = await locker.unlockToken(borshifyOutcomeProof(proof), proofBlockHeight);
            truffleAssert.eventEmitted(tx1, 'Unlocked', (event) => {
                return fromWei(event.amount) == fromWei(amountToUnlock)
                    && event.recipient == addr1;
            });

            const lockerAfterBalance1 = await token.balanceOf(locker.address);
            expect((fromWei(lockerPreBalance1) - fromWei(lockerAfterBalance1)).toString()).equal(fromWei(amountToUnlock));
            const receiverAfterBalance1 = await token.balanceOf(addr1);
            expect((fromWei(receiverAfterBalance1) - fromWei(receiverPreBalance1)).toString()).equal(fromWei(amountToUnlock));

            // Let's pause the Unlock method
            await locker.adminPause(PAUSED_UNLOCK, { from: addr });

            // Let's try to unlock while the unlock is paused.
            // The balance shouldn't be changed and the revert should occur
            await expectRevert.unspecified(locker.unlockToken(borshifyOutcomeProof(proof), proofBlockHeight));
            const lockerAfterBalance2 = await token.balanceOf(locker.address);
            expect(fromWei(lockerAfterBalance1)).equal(fromWei(lockerAfterBalance2));
            const receiverAfterBalance2 = await token.balanceOf(addr1);
            expect(fromWei(receiverAfterBalance1)).equal(fromWei(receiverAfterBalance2));

            // Let's unpause the Unlock method
            await locker.adminPause(UNPAUSED_ALL, { from: addr });

            // Let's try to lock some tokens one more time after unpausing.
            // This should work again - the balance should be changed and the `Unlocked` event emitted
            let proof2 = proof;
            // Change the receipt_id (to 'AAA..AAA') for the proof2 to make it another proof
            proof2.outcome_proof.outcome.receipt_ids[0] = 'A'.repeat(44);
            const tx3 = await locker.unlockToken(borshifyOutcomeProof(proof2), proofBlockHeight);
            truffleAssert.eventEmitted(tx3, 'Unlocked', (event) => {
                return fromWei(event.amount) == fromWei(amountToUnlock)
                    && event.recipient == addr1;
            });
            const lockerAfterBalance3 = await token.balanceOf(locker.address);
            expect((fromWei(lockerAfterBalance1) - fromWei(lockerAfterBalance3)).toString()).equal(fromWei(amountToUnlock));
            const receiverAfterBalance3 = await token.balanceOf(addr1);
            expect((fromWei(receiverAfterBalance3) - fromWei(receiverAfterBalance1)).toString()).equal(fromWei(amountToUnlock));
        });
    });

    /*it('deposit & withdraw', async function() {
        assert(await locker.isBridgeToken(btoken.address));
        expect(await locker.ethToNearToken(btoken.address)).equal(nearToken);
        expect(await locker.nearToEthToken(nearToken)).equal(btoken.address);

        const beforeBalance = await btoken.balanceOf(addr1);
        expect(fromWei(beforeBalance)).equal('0');

        let proof = require('./proof_template.json');
        proof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'Deposit', {
            amount: toWei('10'),
            recipient: hexToBytes(addr1),
            token: nearToken
        }).toString('base64');
        const tx = await locker.deposit(borshifyOutcomeProof(proof), 1099);
        truffleAssert.eventEmitted(tx, 'Deposit', (event) => {
            return event.recipient == addr1 && fromWei(event.amount) == 10;
        });
        const afterBalance = await btoken.balanceOf(addr1);
        expect(fromWei(afterBalance)).equal('10');

        // Withdraw back 5.
        await btoken.approve(locker.address, toWei('5'), { from: addr1 });
        const tx2 = await locker.withdraw(btoken.address, toWei('5'), 'user1', { from: addr1 });
        truffleAssert.eventEmitted(tx2, 'Withdraw', (event) => {
            return event.token == nearToken && event.sender == addr1 && event.amount == toWei('5') && event.recipient == 'user1';
        });
        const afterBalance2 = await btoken.balanceOf(addr1);
        expect(fromWei(afterBalance2)).equal('5');
    });*/

    it('admin functions', async function () {
        expect(await locker.admin()).equal(addr)
        try {
            await locker.adminTransfer(token.address, addr1, toWei('1'), { from: addr1 })
            assert(false)
        } catch (_) { }
        await locker.adminTransfer(token.address, addr1, toWei('1'), { from: addr })
        expect(fromWei(await token.balanceOf(addr1))).to.be.equal('6')
    });
});
