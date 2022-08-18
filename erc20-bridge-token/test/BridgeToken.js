const { expect } = require('chai')
const { ethers, upgrades } = require('hardhat')
const { serialize } = require('rainbow-bridge-lib/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/borshify-proof.js');
const { SCHEMA, createEmptyToken, createDefaultERC20Metadata, ADMIN_ROLE, RESULT_PREFIX_LOCK } = require('./helpers.js');

describe('BridgeToken', () => {
  const nearTokenId = 'nearfuntoken'
  const minBlockAcceptanceHeight = 0

  let BridgeTokenInstance
  let BridgeTokenFactory
  let ProofConsumer
  let adminAccount
  let user

  beforeEach(async function () {
    const [deployerAccount, userAccount] = await ethers.getSigners()
    user = userAccount
    // Make the deployer admin
    adminAccount = deployerAccount
    BridgeTokenInstance = await ethers.getContractFactory('BridgeToken')
    const ProverMock = await (await (await ethers.getContractFactory('NearProverMock')).deploy()).deployed()
    ProofConsumer = await (await (await ethers.getContractFactory('ProofConsumer')).deploy(Buffer.from('nearfuntoken', 'utf-8'), ProverMock.address, minBlockAcceptanceHeight)).deployed()
    BridgeTokenFactory = await ethers.getContractFactory('BridgeTokenFactory')
    BridgeTokenFactory = await upgrades.deployProxy(BridgeTokenFactory, [ProofConsumer.address], { initializer: 'initialize' })
    await ProofConsumer.transferOwnership(BridgeTokenFactory.address);
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

  it('cant create token if token already exists', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await expect(
      createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)

    )
      .to
      .be
      .revertedWith('ERR_TOKEN_EXIST')

  })
  it('can update metadata', async function () {
    const { token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');

    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);
    expect(await token.name()).to.equal('NEAR ERC20')
    expect(await token.symbol()).to.equal('NEAR')
    expect((await token.decimals()).toString()).to.equal('18')
    expect((await token.metadataLastUpdated()).toString()).to.equal('1089')
  })

  it('cannot update metadata with old block height', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);
    // Change the receipt_id (to 'AAA..AAA') for the lockResultProof to make it another metadataProof
    metadataProof.outcome_proof.outcome.receipt_ids[0] = 'A'.repeat(44);
    // Change the block height to make it an old metadataProof
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1087)).toString('base64');
    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1087)
    )
      .to
      .be
      .revertedWith('ERR_OLD_METADATA');
  })

  it('cannot update metadata of nonexistent token', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata("nonexisting-token", 1089)).toString('base64');
    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089)
    )
      .to
      .be
      .revertedWith('ERR_NOT_BRIDGE_TOKEN');
  })

  it('cannot update metadata when paused', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId)).toString('base64');

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
    const { token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const amountToTransfer = 100;
    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue =
      serialize(
        SCHEMA, 'LockResult', {
          prefix: RESULT_PREFIX_LOCK,
          token: nearTokenId,
          amount: amountToTransfer,
          recipient: ethers.utils.arrayify(adminAccount.address),
        }
    )
      .toString('base64');

    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'B'.repeat(44);

    // Deposit and verify event is emitted
    await expect(
        BridgeTokenFactory
          .deposit(borshifyOutcomeProof(metadataProof), 1090)
    )
      .to
      .emit(BridgeTokenFactory, 'Deposit')
      .withArgs(nearTokenId, amountToTransfer, adminAccount.address);

    expect(
      (await token.balanceOf(adminAccount.address))
          .toString()
    )
      .to
      .be
      .equal(amountToTransfer.toString())
  })

  it('cant deposit if contract paused', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'C'.repeat(44);
    await BridgeTokenFactory.pause()
    await expect(
      BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090)
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })
  it('withdraw token', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'D'.repeat(44);
    await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 2);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);

    await BridgeTokenFactory.withdraw(nearTokenId, 100, 'testrecipient.near')
    expect((await token.balanceOf(adminAccount.address)).toString()).to.be.equal('0')
  })

  it('cant withdraw token when paused', async function () {
    const { tokenProxyAddress } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)

    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'F'.repeat(44);
    await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 2);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);
    await BridgeTokenFactory.pause()
    await expect(
      BridgeTokenFactory.withdraw(nearTokenId, 100, 'testrecipient.near')
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })

  it('can deposit and withdraw after unpausing', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)

    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'G'.repeat(44);
    await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 2);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);
    await BridgeTokenFactory.pause()
    await expect(
      BridgeTokenFactory.withdraw(nearTokenId, 100, 'testrecipient.near')
    )
      .to
      .be
      .revertedWith('Pausable: paused');
    await BridgeTokenFactory.unpause()

    await BridgeTokenFactory.withdraw(nearTokenId, 100, 'testrecipient.near')
    expect((await token.balanceOf(adminAccount.address)).toString()).to.be.equal('0')
  })

  it('upgrade token contract', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'B'.repeat(44);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);

    expect((await token.balanceOf(adminAccount.address)).toString()).to.be.equal('100')

    const BridgeTokenV2Instance = await ethers.getContractFactory("TestBridgeToken");
    const BridgeTokenV2 = await (await BridgeTokenV2Instance.deploy()).deployed();

    await BridgeTokenFactory.upgradeToken(nearTokenId, BridgeTokenV2.address)
    const BridgeTokenV2Proxied = BridgeTokenV2Instance.attach(tokenProxyAddress)
    expect(await BridgeTokenV2Proxied.returnTestString()).to.equal('test')
    expect(await BridgeTokenV2Proxied.name()).to.equal('NEAR ERC20')
    expect(await BridgeTokenV2Proxied.symbol()).to.equal('NEAR')
    expect((await BridgeTokenV2Proxied.decimals()).toString()).to.equal('18')
    expect((await BridgeTokenV2Proxied.metadataLastUpdated()).toString()).to.equal('1089')
  })

  it('user cant upgrade token contract', async function () {
    const { token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const metadataProof = require('./proof_template.json');
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, 1089)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), 1089);

    const lockResultProof = metadataProof;
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: 100,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'C'.repeat(44);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(metadataProof), 1090);

    expect((await token.balanceOf(adminAccount.address)).toString()).to.be.equal('100')

    const BridgeTokenV2Instance = await ethers.getContractFactory("TestBridgeToken");
    const BridgeTokenV2 = await (await BridgeTokenV2Instance.deploy()).deployed();

    await expect(BridgeTokenFactory.connect(user).upgradeToken(nearTokenId, BridgeTokenV2.address))
      .to
      .be
      .revertedWith(`AccessControl: account ${user.address.toLowerCase()} is missing role ${ADMIN_ROLE}`);
  })

  describe("Whitelist", function() {
    let tokenInfo;
    let testProofId = 1;
    const recipient = "testrecipient.near";

    beforeEach(async function() {
      tokenInfo = await createEmptyToken(
        nearTokenId,
        BridgeTokenFactory,
        BridgeTokenInstance
      );
      const metadataProof = require("./proof_template.json");
      metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(
        SCHEMA,
        "SetMetadataResult",
        createDefaultERC20Metadata(nearTokenId, 1089)
      ).toString("base64");
      await BridgeTokenFactory.setMetadata(
        borshifyOutcomeProof(metadataProof),
        1089
      );

      const lockResultProof = metadataProof;
      lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(
        SCHEMA,
        "LockResult",
        {
          prefix: RESULT_PREFIX_LOCK,
          token: nearTokenId,
          amount: 100,
          recipient: ethers.utils.arrayify(adminAccount.address),
        }
      ).toString("base64");
      const source = "123456789FGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      lockResultProof.outcome_proof.outcome.receipt_ids[0] = source[
        testProofId
      ].repeat(44);
      testProofId += 1;
      await BridgeTokenFactory.deposit(
        borshifyOutcomeProof(metadataProof),
        1090
      );
    });

    it("Test account in whitelist", async function() {
      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 3);
      await BridgeTokenFactory.addAccountToWhitelist(
        nearTokenId,
        adminAccount.address
      );
      await BridgeTokenFactory.withdraw(nearTokenId, 100, recipient);
      expect(
        (await tokenInfo.token.balanceOf(adminAccount.address)).toString()
      ).to.be.equal("0");
    });

    it("Test token in whitelist", async function() {
      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 2);
      await BridgeTokenFactory.withdraw(nearTokenId, 100, recipient);
      expect(
        (await tokenInfo.token.balanceOf(adminAccount.address)).toString()
      ).to.be.equal("0");
    });

    it("Test token or account not in whitelist", async function() {
      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, 100, recipient)
      ).to.be.revertedWith("ERR_NOT_INITIALIZED_WHITELIST_TOKEN");

      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 1);
      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, 100, recipient)
      ).to.be.revertedWith("ERR_WHITELIST_TOKEN_BLOCKED");

      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, 3);

      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, 100, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      // Disable whitelist mode
      await BridgeTokenFactory.disableWhitelistMode();
      await BridgeTokenFactory.withdraw(nearTokenId, 50, recipient);
      expect(
        (await tokenInfo.token.balanceOf(adminAccount.address)).toString()
      ).to.be.equal("50");

      // Enable whitelist mode
      await BridgeTokenFactory.enableWhitelistMode();
      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, 100, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      await BridgeTokenFactory.addAccountToWhitelist(
        nearTokenId,
        adminAccount.address
      );
      await BridgeTokenFactory.withdraw(nearTokenId, 50, recipient);

      expect(
        (await tokenInfo.token.balanceOf(adminAccount.address)).toString()
      ).to.be.equal("0");
    });
  });
})
