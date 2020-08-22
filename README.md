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
    tokens: UnorderedMap<EvmAddress, AccountId>;
}

impl BridgeTokenFactory {
  /// Relays the lock event from Ethereum.
  /// If given token doesn't exist yet in `tokens` map, create new one
  /// Name will be <hex(evm_address)>.<current_id>
  /// Send `mint` action to that token.
  pub fn deposit();
  
  /// Withdraws funds from NEAR to Ethereum.
  /// This will burn the token in the appropriate BridgeToken contract.
  /// And create an event for Ethereum to unlock the token.
  pub fn withdraw(token_account: AccountId, amount: Balance, recipient: EvmAddress);

  // Deploys BridgeToken contract to the given address.
  fn deploy_bridge_token(account_id: AccountId);
}

struct BridgeToken {
   controller: AccountId;
   token: Token; // uses https://github.com/ilblackdragon/balancer-near/tree/master/near-lib-rs
}

impl BridgeToken {
   pub fn new(controller: AccountId) -> Self {
       Self { controller, token: Token::new() }
   }

   pub fn mint(account_id: AccountId, amount: Balance) {
       assert_eq!(env::predecessor_id(), self.controller, "Only controller is allowed to mint the tokens");
       self.token.mint(account_id, amount);
   }

   pub fn burn(account_id: AccountId, amount: Balance) {
       assert_eq!(env::predecessor_id(), self.controller, "Only controller is allowed to mint the tokens");
       self.token.burn(account_id, amount);
   }
}

impl FungibleToken for BridgeToken {
   ... // see example https://github.com/ilblackdragon/balancer-near/blob/master/balancer-pool/src/lib.rs#L329
}
```