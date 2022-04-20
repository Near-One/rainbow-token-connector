const { expect } = require('chai');
const truffleAssert = require('truffle-assertions');
const BridgeToken = artifacts.require('BridgeToken.sol');

const { toWei, fromWei, hexToBytes } = web3.utils;

contract('BridgeToken', function ([_, addr1]) {
    beforeEach(async function () {
        
    });

    it('can create empty token', async function() {
        const token = await BridgeToken.new("", "", 0);
        expect(await token.name()).to.equal("");
        expect(await token.symbol()).to.equal("");
        expect((await token.decimals()).toString()).to.equal("0");
        expect((await token.metadataLastUpdated()).toString()).to.equal("0");
    });

    it('can update metadata', async function() {
        const token = await BridgeToken.new();        
        let block = await web3.eth.getBlock("latest");
        await token.initialize("", "", 0)
        await token.set_metadata("NEAR ERC20", "NEAR", "18", String(block.number));
        expect(await token.name()).to.equal("NEAR ERC20");
        expect(await token.symbol()).to.equal("NEAR");
        expect((await token.decimals()).toString()).to.equal("18");
        expect((await token.metadataLastUpdated()).toString()).to.equal(String(block.number));
    });

    it('cannot update metadata with old block height', async function() {
        const token = await BridgeToken.new("", "", 0);        
        let block = await web3.eth.getBlock("latest");
        truffleAssert.reverts(token.set_metadata("NEAR ERC20", "NEAR", "18", String(block.number - 1)));
    });

});