use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::PromiseOrValue;

use crate::*;
use near_sdk::json_types::ValidAccountId;

#[near_bindgen]
impl FungibleTokenReceiver for Contract {
    /// Callback on receiving tokens by this contract.
    /// msg: `Ethereum` address to receive the tokens on.
    fn ft_on_transfer(
        &mut self,
        _sender_id: ValidAccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.check_not_paused(PAUSE_DEPOSIT);
        // Fails if msg is not a valid Ethereum address.
        let eth_address = validate_eth_address(msg);
        // Emit the information for transfer via a separate callback to itself.
        // This is done because there is no event prover and this function must return integer value per FT standard.
        ext_self::finish_deposit(
            env::predecessor_account_id(),
            amount.0,
            eth_address,
            &env::current_account_id(),
            0,
            FT_FINISH_DEPOSIT_GAS,
        );
        PromiseOrValue::Value(U128(0))
    }
}
