use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;

use crate::*;

#[near_bindgen]
impl FungibleTokenReceiver for Contract {
    /// Callback on receiving tokens by this contract.
    /// msg: `Ethereum` address to receive the tokens on.
    #[pause(name = "deposit")]
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.check_whitelist_token(env::predecessor_account_id(), sender_id);
        // Fails if msg is not a valid Ethereum address.
        let eth_address = validate_eth_address(msg);
        // Emit the information for transfer via a separate callback to itself.
        // This is done because there is no event prover and this function must return integer value per FT standard.
        ext_self::ext(env::current_account_id())
            .with_static_gas(FT_FINISH_DEPOSIT_GAS)
            .finish_deposit(env::predecessor_account_id(), amount.0, eth_address);
        PromiseOrValue::Value(U128(0))
    }
}
