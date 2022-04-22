const { expect } = require('chai');
const { ethers, upgrades } = require('hardhat')

describe('BridgeToken', () => {
    const nearTokenId = "test-token"
    const minBlockAcceptanceHeight = 0;
    
    let BridgeToken;
    let BridgeTokenInstance;

    let BridgeTokenFactory;
    let BridgeTokenProxy;
    
    let adminAccount;
    let userAccount1;
    let userAccount2;
    
    beforeEach(async function () {
        [deployerAccount, userAccount1, userAccount2] = await ethers.getSigners();
        // Make the deployer admin
        adminAccount = deployerAccount;
        BridgeTokenInstance = await ethers.getContractFactory('BridgeToken');
        const ProverMock = await (await (await ethers.getContractFactory("NearProverMock")).deploy()).deployed(); 
        BridgeTokenFactory = await ethers.getContractFactory("BridgeTokenFactory");
        BridgeTokenFactory = await upgrades.deployProxy(BridgeTokenFactory, [Buffer.from("near-is-megiddo", "utf-8"), ProverMock.address, minBlockAcceptanceHeight], { initializer: "initialize"});
    });

    it('can create empty token', async function() {
        await BridgeTokenFactory.newBridgeToken(nearTokenId);
        const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId);
        const token = BridgeTokenInstance.attach(tokenProxyAddress);
        expect(await token.name()).to.be.equal("");
        expect(await token.symbol()).to.be.equal("");
        expect((await token.decimals()).toString()).to.be.equal("0");
        expect((await token.metadataLastUpdated()).toString()).to.be.equal("0");
    });



    it('can update metadata', async function() {
        // const token = await BridgeToken.new();        
        // let block = await web3.eth.getBlock("latest");
        // await token.initialize("", "", 0)
        // await token.set_metadata("NEAR ERC20", "NEAR", "18", String(block.number));
        // expect(await token.name()).to.equal("NEAR ERC20");
        // expect(await token.symbol()).to.equal("NEAR");
        // expect((await token.decimals()).toString()).to.equal("18");
        // expect((await token.metadataLastUpdated()).toString()).to.equal(String(block.number));
    });

    it('cannot update metadata with old block height', async function() {
        // const token = await BridgeToken.new("", "", 0);        
        // let block = await web3.eth.getBlock("latest");
        // await expect(
        //     token.set_metadata('NEAR_ERC20', 'NEAR', '18', String(block.number - 1))
        // )
        //     .to
        //     .be
        //     .revertedWith('ERR_OLD_METADATA');
    });

});