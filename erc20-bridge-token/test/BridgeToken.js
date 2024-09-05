const { expect } = require('chai')
const { ethers, upgrades } = require('hardhat')
const { metadataSignature, depositSignature } = require('./signatures')

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
}

describe('BridgeToken', () => {
  const wrappedNearId = 'wrap.testnet'

  let BridgeTokenInstance
  let BridgeTokenFactory
  let adminAccount
  let user1
  let user2

  beforeEach(async function () {
    [adminAccount] = await ethers.getSigners()
    user1 = await ethers.getImpersonatedSigner('0x3A445243376C32fAba679F63586e236F77EA601e')
    user2 = await ethers.getImpersonatedSigner('0x5a08feed678c056650b3eb4a5cb1b9bb6f0fe265');

    await fundAddress(user1.address, "1");
    await fundAddress(user2.address, "1");

    BridgeTokenInstance = await ethers.getContractFactory('BridgeToken')
    const bridgeToken = await BridgeTokenInstance.deploy()
    await bridgeToken.waitForDeployment()

    BridgeTokenFactory = await ethers.getContractFactory('BridgeTokenFactory')
    BridgeTokenFactory = await upgrades.deployProxy(BridgeTokenFactory, [
      await bridgeToken.getAddress(),
      "0xa966f32b64caaee9211d674e698cb72100b5e792"
    ], { initializer: 'initialize' });
    await BridgeTokenFactory.waitForDeployment();
  })

  async function fundAddress(address, amount) {
    const tx = await adminAccount.sendTransaction({
      to: address,
      value: ethers.parseEther(amount)
    });
    await tx.wait();
  }

  async function createToken(tokenId) {
    const { signature, payload } = metadataSignature(tokenId);
  
    await BridgeTokenFactory.newBridgeToken(signature, payload);
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(tokenId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)
    return { tokenProxyAddress, token }
  }

  it('can create a token', async function () {
    await createToken(wrappedNearId);
    const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(wrappedNearId)
    const token = BridgeTokenInstance.attach(tokenProxyAddress)
    expect(await token.name()).to.be.equal('Wrapped NEAR fungible token')
    expect(await token.symbol()).to.be.equal('wNEAR')
    expect((await token.decimals()).toString()).to.be.equal('24')
  })

  it('can\'t create token if token already exists', async function () {
    await createToken(wrappedNearId);
    await expect(createToken(wrappedNearId))
      .to.be.revertedWith('ERR_TOKEN_EXIST')
  })

  it("can update token's metadata", async function() {
    const { token } = await createToken(wrappedNearId);

    await BridgeTokenFactory.setMetadata(wrappedNearId, 'Circle USDC Bridged', 'USDC.E');
    expect(await token.name()).to.equal('Circle USDC Bridged');
    expect(await token.symbol()).to.equal('USDC.E');
  });

  it('can\'t update metadata of non-existent token', async function () {
    await createToken(wrappedNearId);

    await expect(
      BridgeTokenFactory.setMetadata('non-existing', 'Circle USDC', 'USDC')
    ).to.be.revertedWith('ERR_NOT_BRIDGE_TOKEN');
  })

  it('can\'t update metadata as a normal user', async function () {
    await createToken(wrappedNearId);

    await expect(
      BridgeTokenFactory.connect(user1).setMetadata(wrappedNearId, 'Circle USDC', 'USDC')
    ).to.be.revertedWithCustomError(BridgeTokenFactory, 'AccessControlUnauthorizedAccount');
  })

  it('deposit token', async function () {
    const { token } = await createToken(wrappedNearId);

    const { signature, payload } = depositSignature(wrappedNearId, user1.address);

    await expect(
      BridgeTokenFactory
        .deposit(signature, payload)
    )
      .to
      .emit(BridgeTokenFactory, 'Deposit')
      .withArgs(wrappedNearId, 1, payload.recipient);

    expect(
      (await token.balanceOf(payload.recipient))
          .toString()
    )
      .to
      .be
      .equal(payload.amount.toString())
  })

  it('can\'t deposit if the contract is paused', async function () {
    await createToken(wrappedNearId);

    await expect (
      BridgeTokenFactory.pauseDeposit()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit);

    const { signature, payload } = depositSignature(wrappedNearId, user1.address);

    await expect(
      BridgeTokenFactory
        .deposit(signature, payload)
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })

  it('can\'t deposit twice with the same signature', async function () {
    await createToken(wrappedNearId);
    
    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    await BridgeTokenFactory.deposit(signature, payload);

    await expect(
      BridgeTokenFactory.deposit(signature, payload)
    )
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'NonceAlreadyUsed');
  })

  it('can\'t deposit with invalid amount', async function () {
    await createToken(wrappedNearId);
    
    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    payload.amount = 100000;

    await expect(
      BridgeTokenFactory.deposit(signature, payload)
    )
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'InvalidSignature');
  })

  it('can\'t deposit with invalid nonce', async function () {
    await createToken(wrappedNearId);
    
    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    payload.nonce = 99;

    await expect(
      BridgeTokenFactory.deposit(signature, payload)
    )
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'InvalidSignature');
  })

  it('can\'t deposit with invalid token', async function () {
    await createToken(wrappedNearId);
    
    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    payload.token = 'test-token.testnet';

    await expect(
      BridgeTokenFactory.deposit(signature, payload)
    )
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'InvalidSignature');
  })

  it('can\'t deposit with invalid recipient', async function () {
    await createToken(wrappedNearId);
    
    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    payload.recipient = user2.address;

    await expect(
      BridgeTokenFactory.deposit(signature, payload)
    )
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'InvalidSignature');
  })

  it('can\'t deposit with invalid relayer', async function () {
    await createToken(wrappedNearId);
    
    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    payload.relayer = user2.address;

    await expect(
      BridgeTokenFactory.deposit(signature, payload)
    )
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'InvalidSignature');
  })

  it('withdraw token', async function () {
    const { token } = await createToken(wrappedNearId);

    await BridgeTokenFactory.setTokenWhitelistMode(wrappedNearId, WhitelistMode.CheckToken);
    expect(
      await BridgeTokenFactory.getTokenWhitelistMode(wrappedNearId)
    ).to.be.equal(WhitelistMode.CheckToken);

    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    await BridgeTokenFactory.deposit(signature, payload);

    const recipient = 'testrecipient.near';
    await expect(
      BridgeTokenFactory.connect(user1).withdraw(
        wrappedNearId,
        payload.amount,
        recipient
      )
    )
      .to
      .emit(BridgeTokenFactory, "Withdraw")
      .withArgs(
        wrappedNearId,
        user1.address,
        payload.amount,
        recipient,
        await BridgeTokenFactory.nearToEthToken(wrappedNearId)
      );

    expect((await token.balanceOf(user1.address)).toString()).to.be.equal('0')
  })

  it('cant withdraw token when paused', async function () {
    await createToken(wrappedNearId);

    await BridgeTokenFactory.setTokenWhitelistMode(wrappedNearId, WhitelistMode.CheckToken);
    expect(
      await BridgeTokenFactory.getTokenWhitelistMode(wrappedNearId)
    ).to.be.equal(WhitelistMode.CheckToken);

    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    await BridgeTokenFactory.deposit(signature, payload);

    await expect(
      BridgeTokenFactory.pauseWithdraw()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedWithdraw);
    await expect(
      BridgeTokenFactory.withdraw(wrappedNearId, payload.amount, 'testrecipient.near')
    )
      .to
      .be
      .revertedWith('Pausable: paused');
  })

  it('can deposit and withdraw after unpausing', async function () {
    const { token } = await createToken(wrappedNearId);

    await BridgeTokenFactory.setTokenWhitelistMode(wrappedNearId, WhitelistMode.CheckToken);
    expect(
      await BridgeTokenFactory.getTokenWhitelistMode(wrappedNearId)
    ).to.be.equal(WhitelistMode.CheckToken);

    const { signature, payload } = depositSignature(wrappedNearId, user1.address);
    await BridgeTokenFactory.deposit(signature, payload);
  
    await expect(
      BridgeTokenFactory.pauseWithdraw()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedWithdraw);

    await expect(
      BridgeTokenFactory.pause(PauseMode.UnpausedAll)
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.UnpausedAll);

      const recipient = 'testrecipient.near';
      await BridgeTokenFactory.connect(user1).withdraw(
        wrappedNearId,
        payload.amount,
        recipient
      );
  
      expect((await token.balanceOf(user1.address)).toString()).to.be.equal('0')
  })

  it('upgrade token contract', async function () {
    const { tokenProxyAddress } = await createToken(wrappedNearId);

    const BridgeTokenV2Instance = await ethers.getContractFactory("TestBridgeToken");
    const BridgeTokenV2 = await BridgeTokenV2Instance.deploy();
    await BridgeTokenV2.waitForDeployment();

    await BridgeTokenFactory.upgradeToken(wrappedNearId, await BridgeTokenV2.getAddress())
    const BridgeTokenV2Proxied = BridgeTokenV2Instance.attach(tokenProxyAddress)
    expect(await BridgeTokenV2Proxied.returnTestString()).to.equal('test')
    expect(await BridgeTokenV2Proxied.name()).to.equal('Wrapped NEAR fungible token')
    expect(await BridgeTokenV2Proxied.symbol()).to.equal('wNEAR')
    expect((await BridgeTokenV2Proxied.decimals()).toString()).to.equal('24')
  })

  it('user cant upgrade token contract', async function () {
    await createToken(wrappedNearId);

    const BridgeTokenV2Instance = await ethers.getContractFactory("TestBridgeToken");
    const BridgeTokenV2 = await BridgeTokenV2Instance.deploy();
    await BridgeTokenV2.waitForDeployment();

    await expect(BridgeTokenFactory.connect(user1).upgradeToken(wrappedNearId, await BridgeTokenV2.getAddress()))
      .to.be.revertedWithCustomError(BridgeTokenFactory, 'AccessControlUnauthorizedAccount');
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

    // Pause deposit
    await expect(
      BridgeTokenFactory.pauseDeposit()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit | PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.pausedFlags()).to.be.equal(PauseMode.PausedDeposit | PauseMode.PausedWithdraw);

    // Pause deposit again
    await expect(
      BridgeTokenFactory.pauseDeposit()
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.PausedDeposit | PauseMode.PausedWithdraw);
    expect(await BridgeTokenFactory.pausedFlags())
      .to
      .be
      .equal(PauseMode.PausedDeposit | PauseMode.PausedWithdraw);

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

    // Unpause all
    await expect(
      BridgeTokenFactory.pause(PauseMode.UnpausedAll)
    )
      .to
      .emit(BridgeTokenFactory, 'Paused')
      .withArgs(adminAccount.address, PauseMode.UnpausedAll);
    expect(await BridgeTokenFactory.pausedFlags()).to.be.equal(PauseMode.UnpausedAll);

    // Pause all
    await expect(
      BridgeTokenFactory.pauseAll()
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
  })

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
    ).to.be.revertedWithCustomError(BridgeTokenFactory, 'AccessControlUnauthorizedAccount');
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    await expect(
      BridgeTokenFactory.connect(newAdminAccount).enableWhitelistMode()
    ).to.be.revertedWithCustomError(BridgeTokenFactory, 'AccessControlUnauthorizedAccount');
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
    ).to.be.revertedWithCustomError(BridgeTokenFactory, 'AccessControlUnauthorizedAccount');
    expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;

    await expect(
      BridgeTokenFactory.connect(adminAccount).enableWhitelistMode()
    ).to.be.revertedWithCustomError(BridgeTokenFactory, 'AccessControlUnauthorizedAccount');
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
    beforeEach(async function() {
      await BridgeTokenFactory.enableWhitelistMode()
    });

    it("Test account in whitelist", async function() {
      const tokenInfo = await createToken(wrappedNearId);
      
      const { signature, payload } = depositSignature(wrappedNearId, user1.address);
      await BridgeTokenFactory.deposit(signature, payload);

      const recipient = payload.recipient;
      const amountToTransfer = payload.amount;

      await BridgeTokenFactory.setTokenWhitelistMode(wrappedNearId, WhitelistMode.CheckAccountAndToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(wrappedNearId)
      ).to.be.equal(WhitelistMode.CheckAccountAndToken);

      await BridgeTokenFactory.addAccountToWhitelist(
        wrappedNearId,
        user1.address
      );
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          wrappedNearId,
          user1.address
        )
      ).to.be.true;

      await BridgeTokenFactory.connect(user1).withdraw(wrappedNearId, amountToTransfer, recipient);
      expect(
        (await tokenInfo.token.balanceOf(user1.address)).toString()
      ).to.be.equal("0");
    });

    it("Test token in whitelist", async function() {
      const tokenInfo = await createToken(wrappedNearId);
      
      const { signature, payload } = depositSignature(wrappedNearId, user1.address);
      await BridgeTokenFactory.deposit(signature, payload);

      const recipient = payload.recipient;
      const amountToTransfer = payload.amount;

      await BridgeTokenFactory.setTokenWhitelistMode(wrappedNearId, WhitelistMode.CheckToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(wrappedNearId)
      ).to.be.equal(WhitelistMode.CheckToken);

      await BridgeTokenFactory.connect(user1).withdraw(wrappedNearId, amountToTransfer, recipient);
      expect(
        (await tokenInfo.token.balanceOf(user1.address)).toString()
      ).to.be.equal("0");
    });

    it("Test multiple tokens", async function() {
      const whitelistTokens = [
        "wrap.testnet",
        "token-bridge-test.testnet",
      ];
      const blacklistTokens = [
        "blacklisted1.testnet",
        "blacklisted2.testnet",
      ];

      for (token of whitelistTokens) {
        await createToken(token);

        const { signature, payload } = depositSignature(token, user1.address);
        await BridgeTokenFactory.deposit(signature, payload);

        await BridgeTokenFactory.setTokenWhitelistMode(token, WhitelistMode.CheckToken);
        expect(
          await BridgeTokenFactory.getTokenWhitelistMode(token)
        ).to.be.equal(WhitelistMode.CheckToken);
      }

      const amountToWithdraw = 1;
      const recipient = "testrecipient.near";
      for (token of blacklistTokens) {
        await expect(
          BridgeTokenFactory.connect(user1).withdraw(
            token,
            amountToWithdraw,
            recipient
          )
        ).to.be.revertedWith("ERR_NOT_INITIALIZED_WHITELIST_TOKEN");
      }

      for (token of whitelistTokens) {
        await expect(
          BridgeTokenFactory.connect(user1).withdraw(
            token,
            amountToWithdraw,
            recipient
          )
        )
          .to
          .emit(BridgeTokenFactory, "Withdraw")
          .withArgs(
            token,
            user1.address,
            amountToWithdraw,
            recipient,
            await BridgeTokenFactory.nearToEthToken(token)
          );
      }
    });

    it("Test multiple accounts", async function() {
      const whitelistTokens = [
        "wrap.testnet",
        "token-bridge-test.testnet",
      ];

      const whitelistAccounts = [
        user1,
        user2
      ];

      const signers = await ethers.getSigners();
      const blacklistAccounts = signers.slice(0, 2);

      const tokensInfo = [];
      for (token of whitelistTokens) {
        tokensInfo.push(createToken(token));
        await BridgeTokenFactory.setTokenWhitelistMode(token, WhitelistMode.CheckAccountAndToken);
        expect(
          await BridgeTokenFactory.getTokenWhitelistMode(token)
        ).to.be.equal(WhitelistMode.CheckAccountAndToken);

        for (const account of whitelistAccounts) {
          const { signature, payload } = depositSignature(token, account.address);
          await BridgeTokenFactory.deposit(signature, payload);

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

      const amountToWithdraw = 1;
      const recipient = "testrecipient.near";
      for (token of whitelistTokens) {
        for (const account of whitelistAccounts) {
          await expect(
            BridgeTokenFactory.connect(account).withdraw(
              token,
              amountToWithdraw,
              recipient
            )
          )
            .to
            .emit(BridgeTokenFactory, "Withdraw")
            .withArgs(
              token, 
              account.address, 
              amountToWithdraw, 
              recipient,
              await BridgeTokenFactory.nearToEthToken(token)
            );
        }

        for (const account of blacklistAccounts) {
          await expect(
            BridgeTokenFactory.connect(account).withdraw(
              token,
              amountToWithdraw,
              recipient
            )
          ).revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");
        }
      }
    });

    it("Test remove account from whitelist", async function() {
      const tokenInfo = await createToken(wrappedNearId);
      
      const { signature, payload } = depositSignature(wrappedNearId, user2.address);
      await BridgeTokenFactory.deposit(signature, payload);

      await BridgeTokenFactory.setTokenWhitelistMode(wrappedNearId, WhitelistMode.CheckAccountAndToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(wrappedNearId)
      ).to.be.equal(WhitelistMode.CheckAccountAndToken);

      await BridgeTokenFactory.addAccountToWhitelist(
        wrappedNearId,
        user2.address
      );
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          wrappedNearId,
          user2.address
        )
      ).to.be.true;

      const amountToWithdraw = 10;
      const recipient = "testrecipient.near";

      await BridgeTokenFactory.connect(user2).withdraw(wrappedNearId, amountToWithdraw, recipient);

      await BridgeTokenFactory.removeAccountFromWhitelist(wrappedNearId, user2.address);
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          wrappedNearId,
          user2.address
        )
      ).to.be.false;

      await expect(
        BridgeTokenFactory.connect(user2).withdraw(wrappedNearId, amountToWithdraw, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      expect(
        (await tokenInfo.token.balanceOf(user2.address)).toString()
      ).to.be.equal((payload.amount - amountToWithdraw).toString());
    });

    it("Test token or account not in whitelist", async function() {
      const tokenId = "token-bridge-test.testnet";
      const tokenInfo = await createToken(tokenId);
      
      const { signature, payload } = depositSignature(tokenId, user2.address);
      await BridgeTokenFactory.deposit(signature, payload);

      const amountToWithdraw = payload.amount / 2;
      const recipient = "testrecipient.near";

      await expect(
        BridgeTokenFactory.withdraw(tokenId, amountToWithdraw, recipient)
      ).to.be.revertedWith("ERR_NOT_INITIALIZED_WHITELIST_TOKEN");

      await BridgeTokenFactory.setTokenWhitelistMode(tokenId, WhitelistMode.Blocked);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(tokenId)
      ).to.be.equal(WhitelistMode.Blocked);

      await expect(
        BridgeTokenFactory.withdraw(tokenId, amountToWithdraw, recipient)
      ).to.be.revertedWith("ERR_WHITELIST_TOKEN_BLOCKED");

      await BridgeTokenFactory.setTokenWhitelistMode(tokenId, WhitelistMode.CheckAccountAndToken);
      expect(
        await BridgeTokenFactory.getTokenWhitelistMode(tokenId)
      ).to.be.equal(WhitelistMode.CheckAccountAndToken);

      await expect(
        BridgeTokenFactory.withdraw(tokenId, amountToWithdraw, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      // Disable whitelist mode
      await BridgeTokenFactory.disableWhitelistMode();
      expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.false;
      await BridgeTokenFactory.connect(user2).withdraw(tokenId, amountToWithdraw, recipient);
      expect(
        (await tokenInfo.token.balanceOf(user2.address)).toString()
      ).to.be.equal(amountToWithdraw.toString());

      // Enable whitelist mode
      await BridgeTokenFactory.enableWhitelistMode();
      expect(await BridgeTokenFactory.isWhitelistModeEnabled()).to.be.true;
      await expect(
        BridgeTokenFactory.withdraw(tokenId, amountToWithdraw, recipient)
      ).to.be.revertedWith("ERR_ACCOUNT_NOT_IN_WHITELIST");

      await BridgeTokenFactory.addAccountToWhitelist(
        tokenId,
        user2.address
      );
      expect(
        await BridgeTokenFactory.isAccountWhitelistedForToken(
          tokenId,
          user2.address
        )
      ).to.be.true;

      await BridgeTokenFactory.connect(user2).withdraw(tokenId, amountToWithdraw, recipient);

      expect(
        (await tokenInfo.token.balanceOf(user2.address)).toString()
      ).to.be.equal("0");
    });
  });
})
