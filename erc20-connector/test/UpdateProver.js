const ERC20Locker = artifacts.require('ERC20Locker');
const ERC20LockerAdmin = artifacts.require('migrations/ERC20LockerAdmin');
const NearProverMock = artifacts.require('test/NearProverMock');
const TToken = artifacts.require('test/TToken');

contract('UpdateProver', function ([admin]) {
    beforeEach(async function () {
        this.token = await TToken.new();
        this.prover = await NearProverMock.new();
        this.locker = await ERC20Locker.new(Buffer.from('nearfuntoken', 'utf-8'), this.prover.address, admin);
        this.lockerAdmin = await ERC20LockerAdmin.new(this.prover.address);
    });

    it('updateContract', async function () {
        let prover = await this.locker.prover_();
        expect(prover).not.equal("0x0000000000000000000000000000000000000000");
        let data = web3.eth.abi.encodeFunctionSignature("upgrade()");
        result = await this.locker.adminDelegatecall(this.lockerAdmin.address, data, { from: admin });
        prover = await this.locker.prover_();
        expect(prover).to.equal("0x0000000000000000000000000000000000000000");
    });
})