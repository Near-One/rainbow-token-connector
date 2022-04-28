# Generic ERC-20/NEP-141 connector for Rainbow Bridge

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
    pub fn deposit(&mut self, proof: Proof);
  
    /// A callback from BridgeToken contract deployed under this factory.
    /// Is called after tokens are burned there to create an receipt result `(amount, token_address, recipient_address)` for Ethereum to unlock the token.
    pub fn finish_withdraw(token_account: AccountId, amount: Balance, recipient: EvmAddress);
    
    /// Transfers given NEP-21 token from `predecessor_id` to factory to lock.
    /// On success, leaves a receipt result `(amount, token_address, recipient_address)`.
    #[payable]
    pub fn lock(&mut self, token: AccountId, amount: Balance, recipient: String);

    /// Relays the unlock event from Ethereum.
    /// Uses prover to validate that proof is correct and relies on a canonical Ethereum chain.
    /// Uses NEP-21 `transfer` action to move funds to `recipient` account.
    #[payable]
    pub fn unlock(&mut self, proof: Proof);

    /// Deploys BridgeToken contract for the given EVM address in hex code.
    /// The name of new NEP21 compatible contract will be <hex(evm_address)>.<current_id>.
    /// Expects ~35N attached to cover storage for BridgeToken.
    #[payable]
    pub fn deploy_bridge_token(address: String);

    /// Checks if Bridge Token has been successfully deployed with `deploy_bridge_token`.
    /// On success, returns the name of NEP21 contract associated with given address (<hex(evm_address)>.<current_id>).
    /// Otherwise, returns "token do not exists" error.
    pub fn get_bridge_token_account_id(&self, address: String) -> AccountId;
}

struct BridgeToken {
   controller: AccountId,
   token: Token, // uses https://github.com/ilblackdragon/balancer-near/tree/master/near-lib-rs
}

impl BridgeToken {
    /// Setup the Token contract with given factory/controller.
    pub fn new(controller: AccountId) -> Self;

    /// Mint tokens to given user. Only can be called by the controller.
    pub fn mint(&mut self, account_id: AccountId, amount: Balance);

    /// Withdraw tokens from this contract.
    /// Burns sender's tokens and calls controller to create event for relaying.
    pub fn withdraw(&mut self, amount: U128, recipient: String) -> Promise;
}

impl FungibleToken for BridgeToken {
   // see example https://github.com/ilblackdragon/balancer-near/blob/master/balancer-pool/src/lib.rs#L329
}
```

## Setup new ERC-20 on NEAR

To setup token contract on NEAR side, anyone can call `<bridge_token_factory>.deploy_bridge_token(<erc20>)` where `<erc20>` is the address of the token.
With this call must attach the amount of $NEAR to cover storage for (at least 30 $NEAR currently).

This will create `<<hex(erc20)>.<bridge_token_factory>>` NEP21-compatible contract.

## Setup new NEP-141 on Ethereum

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

## Testing

### Testing Ethereum side

```
cd erc20-connector
yarn
yarn run test
```

### Testing NEAR side

```
make res/bridge_token_factory.wasm
cargo test --all
```

# Native Aurora ERC-20/NEP-141 connector

## Usage flow Aurora -> NEAR

1. User sends `<erc20>.approve(<erc20locker>, <amount>)` Aurora transaction.
2. User sends `<AuroraERC20locker>.lock(<erc20>, <amount>, <destination>)` or `<AuroraERC20locker>.lockTokenAsyncOnly(<erc20>, <amount>, <destination>)` Aurora transaction. This transaction will create event which stored in the storage.
3. `AuroraBridgeTokenFactory.deposit(<token>, <lock_event_index>)` will be called by `AsyncAurora` by using the promise that returned by `<AuroraERC20locker>.lockTokenAsyncOnly()`, also, the `deposit` can be called manually from any account.
4. `AuroraBridgeTokenFactory.deposit(<token>, <lock_event_index>)` will call `<AuroraERC20locker>.claim(<erc20>, <lockEventIndex>)` and then `<<hex(erc20)>.<AuroraBridgeTokenFactory>>.mint(<near_account_id>, <amount>)` 
5. `<AuroraERC20locker>.claim(<erc20>, <lockEventIndex>)` will remove and return the lock event.
6. User can use `<<hex(erc20)>.<AuroraBridgeTokenFactory>>` token in other applications now on NEAR.

## Usage flow NEAR - > Aurora

1. User call `<<hex(erc20)>.<AuroraBridgeTokenFactory>.<withdraw>>` which will call `<AuroraBridgeTokenFactory>.<finish_withdraw>>`.
2. `<AuroraBridgeTokenFactory>.<finish_withdraw>>` will call `<AuroraERC20locker>.unlockToken(<erc20>, <amount>, <recipient>)`

For more details please check this discussion https://github.com/aurora-is-near/rainbow-bridge/discussions/726

## Building

### Building locker contract
```
cd native-erc20-connector
yarn
./build.sh
```

### Building factory contract
```
cd bridge-aurora-token-factory
./build.sh
```

## Testing
```
cd sim-tests
cargo test
```