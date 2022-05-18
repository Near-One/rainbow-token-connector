const { expect } = require('chai')
const { ethers, upgrades } = require('hardhat')
const { serialize } = require('rainbow-bridge-lib/rainbow/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/rainbow/borshify-proof.js');



const SCHEMA = {
  'SetMetadataResult': {
    kind: 'struct', fields: [
      ['token', 'string'],
      ['name', 'string'],
      ['symbol', 'string'],
      ['decimals', 'u8'],
      ['blockHeight', 'u64'],
    ]
  },
  'LockResult': {
    kind: 'struct', fields: [
      ['token', 'string'],
      ['amount', 'u128'],
      ['recipient', [20]],
    ]
  }
};



describe('BridgeToken', () => {
  const nearTokenId = 'test-token'
  const minBlockAcceptanceHeight = 0

  let BridgeToken
  let BridgeTokenInstance

  let BridgeTokenFactory
  let BridgeTokenProxy

  let adminAccount
  let userAccount1
  let userAccount2

  beforeEach(async function () {
    const [deployerAccount, userAccount1, userAccount2] = await ethers.getSigners()
    // Make the deployer admin
    adminAccount = deployerAccount
    BridgeTokenInstance = await ethers.getContractFactory('BridgeToken')
    const ProverMock = await (await (await ethers.getContractFactory('NearProverMock')).deploy()).deployed()
    BridgeTokenFactory = await ethers.getContractFactory('BridgeTokenFactory')
    BridgeTokenFactory = await upgrades.deployProxy(BridgeTokenFactory, [Buffer.from('nearfuntoken', 'utf-8'), ProverMock.address, minBlockAcceptanceHeight], { initializer: 'initialize' })
  })

  it('can create empty token', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)
    expect(await token.name()).to.be.equal('')
    expect(await token.symbol()).to.be.equal('')
    expect((await token.decimals()).toString()).to.be.equal('0')
    expect((await token.metadataLastUpdated()).toString()).to.be.equal('0')
  })

  it('can update metadata', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', {
      token: nearTokenId,
      name: 'NEAR ERC20',
      symbol: 'NEAR',
      decimals: 18,
      blockHeight: 1089
    }).toString('base64');


    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);
    expect(await token.name()).to.equal('NEAR ERC20')
    expect(await token.symbol()).to.equal('NEAR')
    expect((await token.decimals()).toString()).to.equal('18')
    expect((await token.metadataLastUpdated()).toString()).to.equal('1089')
  })

  it('cannot update metadata with old block height', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', {
      token: nearTokenId,
      name: 'NEAR ERC20',
      symbol: 'NEAR',
      decimals: 18,
      blockHeight: 1089
    }).toString('base64');


    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);
    // Change the receipt_id (to 'AAA..AAA') for the lockResultProof to make it another metadataProof
    metadataProof.outcome_proof.outcome.receipt_ids[0] = 'A'.repeat(44);
    // Change the block height to make it an old metadataProof
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', {
      token: nearTokenId,
      name: 'NEAR ERC20',
      symbol: 'NEAR',
      decimals: 18,
      blockHeight: 1087
    }).toString('base64');
    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1087)
    )
      .to
      .be
      .revertedWith('ERR_OLD_METADATA');
  })

  it('cannot update metadata when paused', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', {
      token: nearTokenId,
      name: 'NEAR ERC20',
      symbol: 'NEAR',
      decimals: 18,
      blockHeight: 1089
    }).toString('base64');

    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);
    await BridgeTokenFactory.pause()
    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089)
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })

  it('deposit token', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', {
      token: nearTokenId,
      name: 'NEAR ERC20',
      symbol: 'NEAR',
      decimals: 18,
      blockHeight: 1089
    }).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'B'.repeat(44);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);
    expect((await token.balanceOf(adminAccount.address)).toString()).to.be.equal('100')
  })
  it('withdraw token', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)

    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', {
      token: nearTokenId,
      name: 'NEAR ERC20',
      symbol: 'NEAR',
      decimals: 18,
      blockHeight: 1089
    }).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'C'.repeat(44);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);

    await BridgeTokenFactory.withdraw(nearTokenId, tokenProxyAddress, 100, 'testrecipient.near')
    expect((await token.balanceOf(adminAccount.address)).toString()).to.be.equal('0')
  })

})
