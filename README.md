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

This will create `<<hex(erc20)>.<bridge_token_factory>>` NEP141-compatible contract.

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

1. `token-locker` locks NEP141 tokens on NEAR side.

To deposit funds into the locker, call `ft_transfer_call` where `msg` contains Ethereum address the funds should arrive to.
This will emit `<token: String, amount: u128, recipient address: EthAddress>` (which arrives to `deposit` on Ethereum side).

Accepts `Unlock(token: String, sender_id: EthAddress, amount: u256, recipient: String)` event from Ethereum side with a proof, verifies its correctness.
If `recipient` contains ':' will split it into `<recipient, msg>` and do `ft_transfer_call(recipient, amount, None, msg)`. Otherwise will `ft_transfer` to `recipient`.

To get metadata of token to Ethereum, need to call `log_metadata`, which will create a result `<token: String, name: String, symbol: String, decimals: u8, blockHeight: u64>`.

2. `erc20-bridge-token` - `BridgeTokenFactory` and `BridgeToken` Ethereum contracts.

`BridgeTokenFactory` creates new `BridgeToken` that correspond to specific token account id on NEAR side.

`BridgeTokenFactory` receives `deposit` with proof from NEAR, verify them and mint appropriate amounts on recipient addresses.

Calling `withdraw` will burn tokens of this user and will generate event `<token: String, sender_id: EthAddress, amount: u256, recipient: String>` that can be relayed to `token-factory`.

### Caveats

Generally, this connector allows any account to call `ft_transfer_call` opening for potential malicious tokens to be bridged to Ethereum.
The expectation here is that on Ethereum side, the token lists will handle this, as it's the same attack model as malicious tokens on Uniswap and other DEXs.

Using Ethereum `BridgeTokenFactory` contract can always resolve Ethereum address of a contract back to NEAR one to check that it is indeed bridging token from NEAR and is created by this factory.

## Testing

### Testing Ethereum side

```
cd erc20-connector
yarn
yarn run test
```

### Testing NEAR side

```
cd bridge-token-factory
./build.sh
cargo test --all
```
