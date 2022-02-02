const bs58 = require('bs58');
const truffleAssert = require('truffle-assertions');

const { serialize } = require('rainbow-bridge-lib/rainbow/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/rainbow/borshify-proof.js');

const ERC20Locker = artifacts.require('ERC20Locker');
const NearProverMock = artifacts.require('test/NearProverMock');
const TToken = artifacts.require('test/TToken');

const UNPAUSED_ALL = 0;

contract('UpdateProver', function ([admin]) {
    beforeEach(async function () {
        let minBlockAcceptanceHeight = 0;
        this.token = await TToken.new();
        this.prover = await NearProverMock.new();
        this.locker = await ERC20Locker.new(Buffer.from('nearfuntoken', 'utf-8'), this.prover.address, minBlockAcceptanceHeight, admin, UNPAUSED_ALL);
        this.lockerAdmin = await ERC20Locker.new(Buffer.from('nearfuntoken', 'utf-8'), this.prover.address, minBlockAcceptanceHeight, admin, UNPAUSED_ALL);
    });

    it('updateContract', async function () {
        const result = await this.locker.prover();
        console.log(result)
        // const preBalance1 = await this.token.balanceOf(addr1);
        // expect(fromWei(preBalance1)).equal('5');
        // await this.token.approve(this.locker.address, toWei('1'), { from: addr1 });
        // const tx = await this.locker.lockToken(this.token.address, toWei('1'), 'receiver', { from: addr1 });
        // const afterBalance1 = await this.token.balanceOf(addr1);
        // expect(fromWei(afterBalance1)).equal('4');
        // truffleAssert.eventEmitted(tx, 'Locked', (event) => {
        //     return event.token == this.token.address && event.sender == addr1 && fromWei(event.amount) == 1 && event.accountId == 'receiver';
        // });
    });
})
