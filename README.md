# Generic ERC20/NEP21 connector for Rainbow Bridge

## Specification

## Ethereum's side

```solidity
contract ERC20Locker {
  constructor(bytes memory nearTokenFactory, INearProver prover) public;
  function lockToken(IERC20 token, uint256 amount, string memory accountId) public;
  function unlockToken(bytes memory proofData, uint64 proofBlockHeader) public;
}
```

## NEAR's side

```rust
struct BridgeTokenFactory {
    /// The account of the prover that we can use to prove
    pub prover_account: AccountId,
    /// Address of the Ethereum locker contract.
    pub locker_address: [u8; 20],
    /// Hashes of the events that were already used.
    pub used_events: UnorderedSet<Vec<u8>>,
    /// Mapping from Ethereum tokens to NEAR tokens.
    pub tokens: UnorderedMap<EvmAddress, AccountId>;
}

impl BridgeTokenFactory {
    /// Initializes the contract.
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `locker_address`: Ethereum address of the locker contract, in hex.
    #[init]
    pub fn new(prover_account: AccountId, locker_address: String) -> Self;

    /// Relays the lock event from Ethereum.
    /// Uses prover to validate that proof is correct and relies on a canonical Ethereum chain.
    /// Send `mint` action to the token that is specified in the proof.
    #[payable]
    pub fn mint(&mut self, proof: Proof);
  
    /// Withdraws funds from NEAR to Ethereum.
    /// This will burn the token in the appropriate BridgeToken contract.
    /// And create an event for Ethereum to unlock the token.
    pub fn withdraw(token_account: AccountId, amount: Balance, recipient: EvmAddress);
    
    /// Deploys BridgeToken contract for the given EVM address in hex code.
    /// The name of new NEP21 compatible contract will be <hex(evm_address)>.<current_id>.
    #[payable]
    pub fn deploy_bridge_token(address: String);
}

struct BridgeToken {
   controller: AccountId,
   token: Token, // uses https://github.com/ilblackdragon/balancer-near/tree/master/near-lib-rs
}

impl BridgeToken {
   pub fn new(controller: AccountId) -> Self {
       Self { controller, token: Token::new() }
   }

   pub fn mint(&mut self, account_id: AccountId, amount: Balance) {
       assert_eq!(env::predecessor_id(), self.controller, "Only controller is allowed to mint the tokens");
       self.token.mint(account_id, amount);
   }

   pub fn burn(&mut self, account_id: AccountId, amount: Balance) {
       assert_eq!(env::predecessor_id(), self.controller, "Only controller is allowed to mint the tokens");
       self.token.burn(account_id, amount);
   }
}

impl FungibleToken for BridgeToken {
   ... // see example https://github.com/ilblackdragon/balancer-near/blob/master/balancer-pool/src/lib.rs#L329
}
```

## Setup new ERC20 on NEAR

To setup token contract on NEAR side, anyone can call `<bridge_token_factory>.deploy_bridge_token(<erc20>)` where `<erc20>` is the address of the token.
With this call must attach the amount of $NEAR to cover storage for (at least 30 $NEAR currently).

This will create `<<hex(erc20)>.<bridge_token_factory>>` NEP21-compatible contract.

## Setup new NEP21 on Ethereum

TODO

## Usage flow Ethereum -> NEAR

1. User sends `<erc20>.approve(<erc20locker>, <amount>)` Ethereum transaction.
2. User sends `<erc20locker>.lock(<erc20>, <amount>, <destination>)` Ethereum transaction. This transaction will create `Locked` event.
3. Relayers will be sending Ethereum blocks to the `EthClient` on NEAR side.
4. After sufficient number of confirmations on top of the mined Ethereum block that contain the `lock` transaction, user or relayer can call `BridgeTokenFactory.mint(proof)`. Proof is the extracted information from the event on Ethereum side.
5. `BridgeTokenFactory.mint` function will call `EthProver` and verify that proof is correct and relies on a block with sufficient number of confirmations.
6. `EthProver` will return callback to `BridgeTokenFactory` confirming that proof is correct.
7. `BridgeTokenFactory` will call `<<hex(erc20)>.<bridge_token_factory>>.mint(<near_account_id>, <amount>)`.
8. User can use `<<hex(erc20)>.<bridge_token_factory>>` token in other applications now on NEAR.

## Usage flow NEAR -> Ethereum

TODO
