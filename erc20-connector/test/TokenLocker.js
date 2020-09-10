const truffleAssert = require('truffle-assertions');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/rainbow/borshify-proof.js');

const BridgeTokenFactory = artifacts.require('BridgeTokenFactory');
const NearProverMock = artifacts.require('test/NearProverMock');
const TToken = artifacts.require('test/TToken');

contract('TokenLocker', function ([_, addr1]) {
    beforeEach(async function () {
        this.token = await TToken.new();
        this.prover = await NearProverMock.new();
        this.locker = await BridgeTokenFactory.new(Buffer.from('nearfuntoken', 'utf-8'), this.prover.address);
        await this.token.mint(this.locker.address, 10000);
    });

    it('lock Token', async function() {
        await this.token.approve(addr1, 1000);
        const tx = await this.locker.lockToken(this.token.address, 1000, 'receiver');
        // truffleAssert.eventEmitted(tx, 'Locked', (event) => event.amount == 1000 && event.accountId == 'receiver');
    });

    // it('unlock Token', async function () {
    //     const proof1 = borshifyOutcomeProof(require('./proof1.json'));
    //     const lockerBalance = await this.token.balanceOf(this.locker.address);
    //     console.log(`LOCKER BALANCE ${lockerBalance}`);
    //     const receiverBalance = await this.token.balanceOf('0xEC8bE1A5630364292E56D01129E8ee8A9578d7D8');
    //     console.log(`RECEIVER BALANCE ${receiverBalance}`);
    //     // await this.locker.unlockToken(proof1, 1099);
    //     // const balance = await this.token.balanceOf('0xEC8bE1A5630364292E56D01129E8ee8A9578d7D8');
    //     // console.log(`RECEIVER BALANCE ${balance}`);
    // });
});
