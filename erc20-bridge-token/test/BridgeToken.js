const { expect } = require('chai')
const { ethers, upgrades } = require('hardhat')
const { serialize } = require('rainbow-bridge-lib/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/borshify-proof.js');
const { SCHEMA, createEmptyToken, createDefaultERC20Metadata, generateRandomBase58, ADMIN_ROLE, RESULT_PREFIX_LOCK } = require('./helpers.js');

const WhitelistMode = {
  NotInitialized: 0,
  Blocked: 1,
  CheckToken: 2,
  CheckAccountAndToken: 3
}

const PauseMode = {
  UnpausedAll: 0,
  PausedWithdraw: 1,
  PausedDeposit: 2,
  PausedSetMetadata: 4,
}

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

  function getProofTemplate() {
    return {
      proof: require("./proof_template.json"),
      proofBlockHeight: 1089,
    };
  }

  async function setMetadata(nearTokenId, tokenProxyAddress) {
    const { proof: metadataProof, proofBlockHeight } = getProofTemplate();
    const metadata = createDefaultERC20Metadata(nearTokenId, proofBlockHeight);
    metadataProof.outcome_proof.outcome.receipt_ids[0] = generateRandomBase58(64);
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(
      SCHEMA,
      "SetMetadataResult",
      metadata
    ).toString("base64");

    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), proofBlockHeight)
    )
      .to
      .emit(BridgeTokenFactory, "SetMetadata")
      .withArgs(
        tokenProxyAddress,
        metadata.name,
        metadata.symbol,
        metadata.decimals
      );
  }

  async function createToken(nearTokenId) {
    const tokenInfo = await createEmptyToken(
      nearTokenId,
      BridgeTokenFactory,
      BridgeTokenInstance
    );

    await setMetadata(nearTokenId, tokenInfo.tokenProxyAddress);
    return tokenInfo;
  }

  async function deposit(nearTokenId, amountToLock, recipientAddress) {
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(
      SCHEMA,
      "LockResult",
      {
        prefix: RESULT_PREFIX_LOCK,
        token: nearTokenId,
        amount: amountToLock,
        recipient: ethers.utils.arrayify(recipientAddress),
      }
    ).toString("base64");
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = generateRandomBase58(64);
    await BridgeTokenFactory.deposit(
      borshifyOutcomeProof(lockResultProof),
      proofBlockHeight
    );
  }

  it('can create an empty token', async function () {
    await BridgeTokenFactory.newBridgeToken(nearTokenId)
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)
    expect(await token.name()).to.be.equal('')
    expect(await token.symbol()).to.be.equal('')
    expect((await token.decimals()).toString()).to.be.equal('0')
    expect((await token.metadataLastUpdated()).toString()).to.be.equal('0')
  })

  it('can\'t create token if token already exists', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await expect(
      createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)

    )
      .to
      .be
      .revertedWith('ERR_TOKEN_EXIST')
  })

  it("can update token's metadata", async function() {
    const { tokenProxyAddress, token } = await createEmptyToken(
      nearTokenId,
      BridgeTokenFactory,
      BridgeTokenInstance
    );

    await setMetadata(nearTokenId, tokenProxyAddress);
    expect(await token.name()).to.equal("NEAR ERC20");
    expect(await token.symbol()).to.equal("NEAR");
    expect((await token.decimals()).toString()).to.equal("18");
    expect((await token.metadataLastUpdated()).toString()).to.equal("1089");
  });

  it('can\'t update metadata with old block height', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const { proof: metadataProof, proofBlockHeight } = getProofTemplate();
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, proofBlockHeight)).toString('base64');
    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), proofBlockHeight);
    // Change the receipt_id (to 'AAA..AAA') for the lockResultProof to make it another metadataProof
    metadataProof.outcome_proof.outcome.receipt_ids[0] = 'A'.repeat(44);
    // Change the block height to make it an old metadataProof
    const oldProofBlockHeight = proofBlockHeight - 1;
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId, oldProofBlockHeight)).toString('base64');
    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), oldProofBlockHeight)
    )
      .to
      .be
      .revertedWith('ERR_OLD_METADATA');
  })

  it('can\'t update metadata of non-existent token', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const { proof: metadataProof, proofBlockHeight } = getProofTemplate();

    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(
      SCHEMA,
      'SetMetadataResult',
      createDefaultERC20Metadata("nonexisting-token", proofBlockHeight)
    ).toString('base64');

    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), proofBlockHeight)
    )
      .to
      .be
      .revertedWith('ERR_NOT_BRIDGE_TOKEN');
  })

  it('can\'t update metadata when paused', async function () {
    await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    const { proof: metadataProof, proofBlockHeight } = getProofTemplate();
    metadataProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'SetMetadataResult', createDefaultERC20Metadata(nearTokenId)).toString('base64');

    await BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), proofBlockHeight);
    await expect (
      BridgeTokenFactory.pauseSetMetadata()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedSetMetadata);

    await expect(
      BridgeTokenFactory.setMetadata(borshifyOutcomeProof(metadataProof), proofBlockHeight)
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })

  it('deposit token', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(
      nearTokenId,
      BridgeTokenFactory,
      BridgeTokenInstance
    );

    setMetadata(nearTokenId, tokenProxyAddress);

    const amountToTransfer = 100;
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue =
      serialize(
        SCHEMA, 'LockResult', {
          prefix: RESULT_PREFIX_LOCK,
          token: nearTokenId,
          amount: amountToTransfer,
          recipient: ethers.utils.arrayify(user.address),
        }
    )
      .toString('base64');

    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'B'.repeat(44);

    // Deposit and verify event is emitted
    await expect(
        BridgeTokenFactory
          .deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight)
    )
      .to
      .emit(BridgeTokenFactory, 'Deposit')
      .withArgs(nearTokenId, amountToTransfer, user.address);

    expect(
      (await token.balanceOf(user.address))
          .toString()
    )
      .to
      .be
      .equal(amountToTransfer.toString())
  })

  it('can\'t deposit if the contract is paused', async function () {
    let {tokenProxyAddress} = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await setMetadata(nearTokenId, tokenProxyAddress);

    const amountToTransfer = 100;
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: amountToTransfer,
      recipient: ethers.utils.arrayify(adminAccount.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'C'.repeat(44);
    await expect (
      BridgeTokenFactory.pauseDeposit()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit);

    await expect(
      BridgeTokenFactory.deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight)
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })
  it('withdraw token', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await setMetadata(nearTokenId, tokenProxyAddress);

    const amountToTransfer = 100;
    const recipient = "testrecipient.near";
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: amountToTransfer,
      recipient: ethers.utils.arrayify(user.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'D'.repeat(44);

    await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckToken);
    expect(
      await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
    ).to.be.equal(WhitelistMode.CheckToken);

    await BridgeTokenFactory.deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight);

    await expect(
      BridgeTokenFactory.connect(user).withdraw(
        nearTokenId,
        amountToTransfer,
        recipient
      )
    )
      .to
      .emit(BridgeTokenFactory, "Withdraw")
      .withArgs(
        nearTokenId,
        user.address,
        amountToTransfer,
        recipient,
        await BridgeTokenFactory.nearToEthToken(nearTokenId)
      );

    expect((await token.balanceOf(user.address)).toString()).to.be.equal('0')
  })

  it('cant withdraw token when paused', async function () {
    const { tokenProxyAddress } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await setMetadata(nearTokenId, tokenProxyAddress);

    const amountToTransfer = 100;
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: amountToTransfer,
      recipient: ethers.utils.arrayify(user.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'F'.repeat(44);

    await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckToken);
    expect(
      await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
    ).to.be.equal(WhitelistMode.CheckToken);

    await BridgeTokenFactory.deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight);
    await expect(
      BridgeTokenFactory.pauseWithdraw()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedWithdraw);
    await expect(
      BridgeTokenFactory.withdraw(nearTokenId, amountToTransfer, 'testrecipient.near')
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })

  it('can deposit and withdraw after unpausing', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await setMetadata(nearTokenId, tokenProxyAddress);

    const amountToTransfer = 100;
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: amountToTransfer,
      recipient: ethers.utils.arrayify(user.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'G'.repeat(44);

    await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckToken);
    expect(
      await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
    ).to.be.equal(WhitelistMode.CheckToken);

    await BridgeTokenFactory.deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight);
    await expect(
      BridgeTokenFactory.pauseWithdraw()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedWithdraw);

    await expect(
      BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, 'testrecipient.near')
    )
      .to
      .be
      .revertedWith('Pausable: paused');

    await expect(
      BridgeTokenFactory.pause(PauseMode.UnpausedAll)
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.UnpausedAll);


    await BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, 'testrecipient.near')
    expect((await token.balanceOf(user.address)).toString()).to.be.equal('0')
  })

  it('upgrade token contract', async function () {
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await setMetadata(nearTokenId, tokenProxyAddress);

    const amountToTransfer = 100;
    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: amountToTransfer,
      recipient: ethers.utils.arrayify(user.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'B'.repeat(44);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight);

    expect((await token.balanceOf(user.address)).toString()).to.be.equal(amountToTransfer.toString())

    const BridgeTokenV2Instance = await ethers.getContractFactory("TestBridgeToken");
    const BridgeTokenV2 = await (await BridgeTokenV2Instance.deploy()).deployed();

    await BridgeTokenFactory.upgradeToken(nearTokenId, BridgeTokenV2.address)
    const BridgeTokenV2Proxied = BridgeTokenV2Instance.attach(tokenProxyAddress)
    expect(await BridgeTokenV2Proxied.returnTestString()).to.equal('test')
    expect(await BridgeTokenV2Proxied.name()).to.equal('NEAR ERC20')
    expect(await BridgeTokenV2Proxied.symbol()).to.equal('NEAR')
    expect((await BridgeTokenV2Proxied.decimals()).toString()).to.equal('18')
    expect((await BridgeTokenV2Proxied.metadataLastUpdated()).toString()).to.equal(proofBlockHeight.toString())
  })

  it('user cant upgrade token contract', async function () {
    const amountToTransfer = 100;
    const { tokenProxyAddress, token } = await createEmptyToken(nearTokenId, BridgeTokenFactory, BridgeTokenInstance)
    await setMetadata(nearTokenId, tokenProxyAddress);

    const { proof: lockResultProof, proofBlockHeight } = getProofTemplate();
    lockResultProof.outcome_proof.outcome.status.SuccessValue = serialize(SCHEMA, 'LockResult', {
      prefix: RESULT_PREFIX_LOCK,
      token: nearTokenId,
      amount: amountToTransfer,
      recipient: ethers.utils.arrayify(user.address),
    }).toString('base64');
    lockResultProof.outcome_proof.outcome.receipt_ids[0] = 'C'.repeat(44);
    await BridgeTokenFactory.deposit(borshifyOutcomeProof(lockResultProof), proofBlockHeight);

    expect((await token.balanceOf(user.address)).toString()).to.be.equal(amountToTransfer.toString())

    const BridgeTokenV2Instance = await ethers.getContractFactory("TestBridgeToken");
    const BridgeTokenV2 = await (await BridgeTokenV2Instance.deploy()).deployed();

    await expect(BridgeTokenFactory.connect(user).upgradeToken(nearTokenId, BridgeTokenV2.address))
      .to
      .be
      .revertedWith(`AccessControl: account ${user.address.toLowerCase()} is missing role ${ADMIN_ROLE}`);
  })

  it('Test selective pause', async function () {
    // Pause withdraw
    await expect(
      BridgeTokenFactory.pauseWithdraw()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.pausedFlags()).to.be.equal(PauseMode.PausedWithdraw);

    // Pause withdraw again
    await expect(
      BridgeTokenFactory.pauseWithdraw()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.pausedFlags()).to.be.equal(PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.paused(PauseMode.PausedDeposit)).to.be.equal(false);
    expect(await BridgeTokenFactory.paused(PauseMode.PausedWithdraw)).to.be.equal(true);
    expect(await BridgeTokenFactory.paused(PauseMode.PausedSetMetadata)).to.be.equal(false);

    // Pause deposit
    await expect(
      BridgeTokenFactory.pauseDeposit()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit | PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.pausedFlags()).to.be.equal(PauseMode.PausedDeposit | PauseMode.PausedWithdraw);

    // Pause set metadata
    await expect(
      BridgeTokenFactory.pauseSetMetadata()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit | PauseMode.PausedWithdraw | PauseMode.PausedSetMetadata);
    expect(await BridgeTokenFactory.pausedFlags())
      .to
      .be
      .equal(PauseMode.PausedDeposit | PauseMode.PausedWithdraw | PauseMode.PausedSetMetadata);

    // Pause deposit again
    await expect(
      BridgeTokenFactory.pauseDeposit()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit | PauseMode.PausedWithdraw | PauseMode.PausedSetMetadata);
    expect(await BridgeTokenFactory.pausedFlags())
      .to
      .be
      .equal(PauseMode.PausedDeposit | PauseMode.PausedWithdraw | PauseMode.PausedSetMetadata);

    // Pause deposit and withdraw
    await expect(
      BridgeTokenFactory.pause(PauseMode.PausedDeposit | PauseMode.PausedWithdraw)
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit | PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.pausedFlags())
      .to
      .be
      .equal(PauseMode.PausedDeposit | PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.paused(PauseMode.PausedDeposit)).to.be.equal(true);
    expect(await BridgeTokenFactory.paused(PauseMode.PausedWithdraw)).to.be.equal(true);
    expect(await BridgeTokenFactory.paused(PauseMode.PausedSetMetadata)).to.be.equal(false);

    // Unpause all
    await expect(
      BridgeTokenFactory.pause(PauseMode.UnpausedAll)
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.UnpausedAll);
    expect(await BridgeTokenFactory.pausedFlags()).to.be.equal(PauseMode.UnpausedAll);
  })

  it("Test setProofConsumer ", async function() {
    expect(
      (await BridgeTokenFactory.proofConsumerAddress()).toLowerCase()
    )
      .to
      .be
      .equal(ProofConsumer.address.toLowerCase());

    const newProofConsumerAddress = "0x0123456789abcdefdeadbeef0123456789abcdef";
    await BridgeTokenFactory.setProofConsumer(newProofConsumerAddress);
    expect(
      (await BridgeTokenFactory.proofConsumerAddress()).toLowerCase()
    )
      .to
      .be
      .equal(newProofConsumerAddress);
  });

  it("Test grant admin role", async function() {
    await BridgeTokenFactory.connect(adminAccount).disableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.false;

    await BridgeTokenFactory.connect(adminAccount).enableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    const signers = await ethers.getSigners();
    const newAdminAccount = signers[2];
    const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000";
    await expect(
      BridgeTokenFactory.connect(newAdminAccount).disableWhitelistMode()
    ).to.be.revertedWith(
      `is missing role ${DEFAULT_ADMIN_ROLE}`
    );
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    await expect(
      BridgeTokenFactory.connect(newAdminAccount).enableWhitelistMode()
    ).to.be.revertedWith(
      `is missing role ${DEFAULT_ADMIN_ROLE}`
    );
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    // Grant DEFAULT_ADMIN_ROLE to newAdminAccount
    await expect(
      BridgeTokenFactory.grantRole(DEFAULT_ADMIN_ROLE, newAdminAccount.address)
    )
      .to
      .emit(BridgeTokenFactory, "RoleGranted")
      .withArgs(
        DEFAULT_ADMIN_ROLE,
        newAdminAccount.address,
        adminAccount.address
      );
    await BridgeTokenFactory.connect(newAdminAccount).disableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.false;

    await BridgeTokenFactory.connect(newAdminAccount).enableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    // Revoke DEFAULT_ADMIN_ROLE from adminAccount
    await expect(
      BridgeTokenFactory
        .connect(newAdminAccount)
        .revokeRole(
          DEFAULT_ADMIN_ROLE,
          adminAccount.address
        )
    )
      .to
      .emit(BridgeTokenFactory, "RoleRevoked")
      .withArgs(
        DEFAULT_ADMIN_ROLE,
        adminAccount.address,
        newAdminAccount.address
      );

    // Check tx reverted on call from revoked adminAccount
    await expect(
      BridgeTokenFactory.connect(adminAccount).disableWhitelistMode()
    ).to.be.revertedWith(
      `is missing role ${DEFAULT_ADMIN_ROLE}`
    );
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    await expect(
      BridgeTokenFactory.connect(adminAccount).enableWhitelistMode()
    ).to.be.revertedWith(
      `is missing role ${DEFAULT_ADMIN_ROLE}`
    );
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    // Check newAdminAccount can perform admin calls
    await BridgeTokenFactory.connect(newAdminAccount).disableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.false;
    await BridgeTokenFactory.connect(newAdminAccount).enableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    // Check newAdminAccount can grant DEFAULT_ADMIN_ROLE to adminAccount
    await expect(
      BridgeTokenFactory
        .connect(newAdminAccount)
        .grantRole(DEFAULT_ADMIN_ROLE, adminAccount.address)
    )
      .to
      .emit(BridgeTokenFactory, "RoleGranted")
      .withArgs(
        DEFAULT_ADMIN_ROLE,
        adminAccount.address,
        newAdminAccount.address
      );

    // Check that adminAccount can perform admin calls again
    await BridgeTokenFactory.connect(adminAccount).disableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.false;
    await BridgeTokenFactory.connect(adminAccount).enableWhitelistMode();
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;
  });
  
  describe("Whitelist", function() {
    let tokenInfo;
    const recipient = "testrecipient.near";
    const amountToLock = 100;

    beforeEach(async function() {
      tokenInfo = await createToken(nearTokenId);
      await deposit(nearTokenId, amountToLock, user.address);
    });

    it("Test account in whitelist", async function() {
      const amountToTransfer = amountToLock;
      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckAccountAndToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
      ).to.be.equal(WhitelistMode.CheckAccountAndToken);

      await BridgeTokenFactory.addAccountToWhitelist(
        nearTokenId,
        user.address
      );
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          nearTokenId,
          user.address
        )
      ).to.be.true;

      await BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, recipient);
      expect(
        (await tokenInfo.token.balanceOf(user.address)).toString()
      ).to.be.equal("0");
    });

    it("Test token in whitelist", async function() {
      const amountToTransfer = amountToLock;
      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
      ).to.be.equal(WhitelistMode.CheckToken);

      await BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, recipient);
      expect(
        (await tokenInfo.token.balanceOf(user.address)).toString()
      ).to.be.equal("0");
    });

    it("Test multiple tokens", async function() {
      const amountToTransfer = amountToLock;
      const whitelistTokens = [
        "near-token1.near",
        "near-token2.near",
        "near-token3.near",
        "near-token4.near",
      ];
      const blacklistTokens = [
        "near-token5.near",
        "near-token6.near",
        "near-token7.near",
        "near-token8.near",
      ];

      const tokensInfo = [];
      for (token of whitelistTokens) {
        tokensInfo.push(await createToken(token));
        await deposit(token, amountToTransfer, user.address);
        await BridgeTokenFactory.setTokenWhitelistMode(token, WhitelistMode.CheckToken);
        expect(
          await BridgeTokenFactory.getTokenWhitelistMode(token)
        ).to.be.equal(WhitelistMode.CheckToken);
      }

      for (token of blacklistTokens) {
        await expect(
          BridgeTokenFactory.connect(user).withdraw(
            token,
            amountToTransfer,
            recipient
          )
        ).to.be.revertedWith("ERR_NOT_INITIALIZED_WHITELIST_TOKEN");
      }

      for (token of whitelistTokens) {
        await expect(
          BridgeTokenFactory.connect(user).withdraw(
            token,
            amountToTransfer,
            recipient
          )
        )
          .to
          .emit(BridgeTokenFactory, "Withdraw")
          .withArgs(
            token,
            user.address,
            amountToTransfer,
            recipient,
            await BridgeTokenFactory.nearToEthToken(token)
          );
      }

      for (tokenInfo of tokensInfo) {
        expect(
          (await tokenInfo.token.balanceOf(user.address)).toString()
        ).to.be.equal("0");
      }
    });

    it("Test multiple accounts", async function() {
      const amountToTransfer = amountToLock;
      const whitelistTokens = [
        "near-token1.near",
        "near-token2.near",
        "near-token3.near",
        "near-token4.near",
      ];

      const signers = await ethers.getSigners();
      const numOfSigners = 3;
      const whitelistAccounts = signers.slice(0, numOfSigners);
      const blacklistAccounts = signers.slice(numOfSigners, numOfSigners * 2);

      const tokensInfo = [];
      for (token of whitelistTokens) {
        tokensInfo.push(createToken(token));
        await BridgeTokenFactory.setTokenWhitelistMode(token, WhitelistMode.CheckAccountAndToken);
        expect(
          await BridgeTokenFactory.getTokenWhitelistMode(token)
        ).to.be.equal(WhitelistMode.CheckAccountAndToken);

        for (const account of whitelistAccounts) {
          await deposit(token, amountToTransfer, account.address);
          await BridgeTokenFactory.addAccountToWhitelist(
            token,
            account.address
          );
          expect(
            await BridgeTokenFactory.isAccountWhitelistedForToken(
              token,
              account.address
            )
          ).to.be.true;
        }
      }

      for (token of whitelistTokens) {
        for (const account of whitelistAccounts) {
          await expect(
            BridgeTokenFactory.connect(account).withdraw(
              token,
              amountToTransfer,
              recipient
            )
          )
            .to
            .emit(BridgeTokenFactory, "Withdraw")
            .withArgs(
              token, 
              account.address, 
              amountToTransfer, 
              recipient,
              await BridgeTokenFactory.nearToEthToken(token)
            );
        }

        for (const account of blacklistAccounts) {
          await expect(
            BridgeTokenFactory.connect(account).withdraw(
              token,
              amountToTransfer,
              recipient
            )
          ).revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");
        }
      }
    });

    it("Test remove account from whitelist", async function() {
      const amountToTransfer = amountToLock / 2;
      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckAccountAndToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
      ).to.be.equal(WhitelistMode.CheckAccountAndToken);

      await BridgeTokenFactory.addAccountToWhitelist(
        nearTokenId,
        user.address
      );
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          nearTokenId,
          user.address
        )
      ).to.be.true;

      await BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, recipient);

      await BridgeTokenFactory.removeAccountFromWhitelist(nearTokenId, adminAccount.address);
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          nearTokenId,
          adminAccount.address
        )
      ).to.be.false;

      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, amountToTransfer, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      expect(
        (await tokenInfo.token.balanceOf(user.address)).toString()
      ).to.be.equal(amountToTransfer.toString());
    });

    it("Test token or account not in whitelist", async function() {
      const amountToTransfer = amountToLock / 2;
      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, amountToTransfer, recipient)
      ).to.be.revertedWith("ERR_NOT_INITIALIZED_WHITELIST_TOKEN");

      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.Blocked);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
      ).to.be.equal(WhitelistMode.Blocked);

      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, amountToTransfer, recipient)
      ).to.be.revertedWith("ERR_WHITELIST_TOKEN_BLOCKED");

      await BridgeTokenFactory.setTokenWhitelistMode(nearTokenId, WhitelistMode.CheckAccountAndToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(nearTokenId)
      ).to.be.equal(WhitelistMode.CheckAccountAndToken);

      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, amountToTransfer, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      // Disable whitelist mode
      await BridgeTokenFactory.disableWhitelistMode();
      expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.false;
      await BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, recipient);
      expect(
        (await tokenInfo.token.balanceOf(user.address)).toString()
      ).to.be.equal(amountToTransfer.toString());

      // Enable whitelist mode
      await BridgeTokenFactory.enableWhitelistMode();
      expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;
      await expect(
        BridgeTokenFactory.withdraw(nearTokenId, amountToTransfer, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      await BridgeTokenFactory.addAccountToWhitelist(
        nearTokenId,
        user.address
      );
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          nearTokenId,
          user.address
        )
      ).to.be.true;

      await BridgeTokenFactory.connect(user).withdraw(nearTokenId, amountToTransfer, recipient);

      expect(
        (await tokenInfo.token.balanceOf(user.address)).toString()
      ).to.be.equal("0");
    });
  });
})
