use near_sdk::{assert_one_yocto, ONE_YOCTO};

use crate::*;

fn calculate_fee_amount(transfer_amount: u128, fee: &Fee) -> u128 {
    let fee_amount = (transfer_amount * fee.fee_percentage.0) / FEE_DECIMAL_PRECISION;

    let bounded_fee_amount = if fee.lower_bound.map_or(false, |bound| fee_amount < bound.0) {
        fee.lower_bound.unwrap().0
    } else if fee.upper_bound.map_or(false, |bound| fee_amount > bound.0) {
        fee.upper_bound.unwrap().0
    } else {
        fee_amount
    };

    std::cmp::min(bounded_fee_amount, transfer_amount)
}

#[near_bindgen]
impl BridgeTokenFactory {
    //this should be added as per: 10% -> 0.1 = 0.1*10^6
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_deposit_fee(
        &mut self,
        token: EthAddressHex,
        fee_percentage: U128,
        lower_bound: Option<U128>,
        upper_bound: Option<U128>,
    ) {
        self.deposit_fee.insert(
            &token.0,
            &Fee {
                fee_percentage,
                lower_bound,
                upper_bound,
            },
        );
    }

    #[access_control_any(roles(Role::FeeSetter))]
    pub fn unset_deposit_fee(&mut self, token: EthAddressHex) {
        self.deposit_fee.remove(&token.0);
    }

    // Fee should be added as per: 10% -> 0.1 = 0.1*10^6 with proper fee amount bounds
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_deposit_fee_per_silo(
        &mut self,
        silo_account_id: AccountId,
        token: Option<EthAddressHex>,
        fee_percentage: U128,
        lower_bound: Option<U128>,
        upper_bound: Option<U128>,
    ) {
        self.deposit_fee_per_silo.insert(
            &get_silo_fee_map_key(&silo_account_id, token.as_ref()),
            &Fee {
                fee_percentage,
                lower_bound,
                upper_bound,
            },
        );
    }

    #[access_control_any(roles(Role::FeeSetter))]
    pub fn unset_deposit_fee_per_silo(
        &mut self,
        silo_account_id: AccountId,
        token: Option<EthAddressHex>,
    ) {
        self.deposit_fee_per_silo
            .remove(&get_silo_fee_map_key(&silo_account_id, token.as_ref()));
    }

    // Fee should be added as per: 10% -> 0.1 = 0.1*10^6 with proper fee amount bounds
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_withdraw_fee(
        &mut self,
        token: EthAddressHex,
        fee_percentage: U128,
        lower_bound: Option<U128>,
        upper_bound: Option<U128>,
    ) {
        self.withdraw_fee.insert(
            &token.0,
            &Fee {
                fee_percentage,
                lower_bound,
                upper_bound,
            },
        );
    }

    #[access_control_any(roles(Role::FeeSetter))]
    pub fn unset_withdraw_fee(&mut self, token: EthAddressHex) {
        self.withdraw_fee.remove(&token.0);
    }

    // Fee should be added as per: 10% -> 0.1 = 0.1*10^6 with proper fee amount bounds
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_withdraw_fee_per_silo(
        &mut self,
        silo_account_id: AccountId,
        token: Option<EthAddressHex>,
        fee_percentage: U128,
        lower_bound: Option<U128>,
        upper_bound: Option<U128>,
    ) {
        self.withdraw_fee_per_silo.insert(
            &get_silo_fee_map_key(&silo_account_id, token.as_ref()),
            &Fee {
                fee_percentage,
                lower_bound,
                upper_bound,
            },
        );
    }

    #[access_control_any(roles(Role::FeeSetter))]
    pub fn unset_withdraw_fee_per_silo(
        &mut self,
        silo_account_id: AccountId,
        token: Option<EthAddressHex>,
    ) {
        self.withdraw_fee_per_silo
            .remove(&get_silo_fee_map_key(&silo_account_id, token.as_ref()));
    }

    pub fn get_deposit_fee(&self, token: &EthAddressHex) -> Option<Fee> {
        self.deposit_fee.get(&token.0)
    }

    pub fn get_withdraw_fee(&self, token: &EthAddressHex) -> Option<Fee> {
        self.withdraw_fee.get(&token.0)
    }

    // Returns withdraw fee for different tokens per silo
    pub fn get_withdraw_fee_per_silo(
        &self,
        silo_account_id: AccountId,
        token: Option<EthAddressHex>,
    ) -> Option<Fee> {
        self.get_withdraw_fee_per_silo_internal(&silo_account_id, token.as_ref())
    }

    // Returns desposit fee for different tokens per silo
    pub fn get_desposit_fee_per_silo(
        &self,
        silo_account_id: AccountId,
        token: Option<EthAddressHex>,
    ) -> Option<Fee> {
        self.get_deposit_fee_per_silo_internal(&silo_account_id, token.as_ref())
    }

    // Accumulated fee should be claimed from here.
    #[payable]
    #[access_control_any(roles(Role::FeeClaimer))]
    pub fn claim_fee(&mut self, token: AccountId, amount: Balance) -> Promise {
        assert_one_yocto();
        ext_bridge_token::ext(token)
            .with_static_gas(FT_TRANSFER_GAS)
            .with_attached_deposit(ONE_YOCTO)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
    }

    pub fn calculate_deposit_fee_amount(
        &self,
        token: &EthAddressHex,
        amount: U128,
        target: Option<AccountId>,
    ) -> U128 {
        let Some(deposit_fee) = target
                .and_then(|target| self.get_deposit_fee_per_silo_internal(&target, Some(token)))
                .or_else(|| self.get_deposit_fee(token))
                else { return U128(0) };

        U128(calculate_fee_amount(amount.0, &deposit_fee))
    }

    pub fn calculate_withdraw_fee_amount(
        &self,
        token: &EthAddressHex,
        amount: U128,
        withdrawer: &AccountId,
    ) -> U128 {
        let Some(withdraw_fee) = self.get_withdraw_fee_per_silo_internal(withdrawer, Some(token))
                .or_else(|| self.get_withdraw_fee(token))
                else { return U128(0) };

        U128(calculate_fee_amount(amount.0, &withdraw_fee))
    }

    pub(crate) fn get_withdraw_fee_per_silo_internal(
        &self,
        silo_account_id: &AccountId,
        token: Option<&EthAddressHex>,
    ) -> Option<Fee> {
        if token.is_some() {
            self.withdraw_fee_per_silo
                .get(&get_silo_fee_map_key(&silo_account_id, token))
                .or_else(|| {
                    self.withdraw_fee_per_silo
                        .get(&get_silo_fee_map_key(&silo_account_id, None))
                })
        } else {
            self.withdraw_fee_per_silo
                .get(&get_silo_fee_map_key(&silo_account_id, None))
        }
    }

    pub(crate) fn get_deposit_fee_per_silo_internal(
        &self,
        silo_account_id: &AccountId,
        token: Option<&EthAddressHex>,
    ) -> Option<Fee> {
        if token.is_some() {
            self.deposit_fee_per_silo
                .get(&get_silo_fee_map_key(&silo_account_id, token))
                .or_else(|| {
                    self.deposit_fee_per_silo
                        .get(&get_silo_fee_map_key(&silo_account_id, None))
                })
        } else {
            self.deposit_fee_per_silo
                .get(&get_silo_fee_map_key(&silo_account_id, None))
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::convert::TryInto;

    fn fee_setter() -> AccountId {
        "fee_setter.near".parse().unwrap()
    }

    fn silo_account() -> AccountId {
        "silo.aurora".parse().unwrap()
    }

    #[test]
    fn test_fee_token_bound_for_deposit_fee() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(
            predecessor_account_id: fee_setter(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(token_address.clone());
        // setting fee-percentage and bounds
        contract.set_deposit_fee(
            token_address.clone(),
            U128(50000),
            Some(U128(100)),
            Some(U128(200)),
        );
        let fee = contract.get_deposit_fee(&token_address).unwrap();

        assert_eq!(
            U128(100),
            fee.lower_bound.unwrap(),
            "Lower bound not matched"
        );
        assert_eq!(
            U128(200),
            fee.upper_bound.unwrap(),
            "Upper bound not matched"
        );
    }

    #[test]
    fn test_adujsted_fee_amount() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(
            predecessor_account_id: fee_setter(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(token_address.clone());
        // setting fee-percentage and bounds
        contract.set_deposit_fee(
            token_address.clone(),
            U128(50000),
            Some(U128(100)),
            Some(U128(200)),
        );
        // let deposit_bound = contract.set_deposit_fee_bound(&token_address, , U128(100));
        let expected_fee = contract.get_deposit_fee(&token_address).unwrap();
        assert_eq!(
            U128(100),
            expected_fee.lower_bound.unwrap(),
            "Lower bound not matched"
        );
        assert_eq!(
            U128(200),
            expected_fee.upper_bound.unwrap(),
            "Upper bound not matched"
        );

        let expected_fee = contract.get_deposit_fee(&token_address).unwrap();
        assert_eq!(
            U128(50000),
            expected_fee.fee_percentage,
            "Eth -> Near fee percentage not matched for deposit"
        );
        let adjusted_fee_amount = calculate_fee_amount(100u128, &expected_fee);
        assert_eq!(
            adjusted_fee_amount,
            expected_fee.lower_bound.unwrap().0,
            "Adjusted fee amount didn't matched as expected"
        );
    }

    #[test]
    #[should_panic]
    fn test_fee_setter_for_deposit_with_unallowed_role() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        set_env!(predecessor_account_id: bob()); // bob is not allowed (has no role) to set deposit-fees;
        contract.set_deposit_fee(token_address, U128(50000), Some(U128(100)), Some(U128(200)));
    }

    #[test]
    fn test_fee_token_bound_for_withdraw_fee() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(4);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(
            predecessor_account_id: fee_setter(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(token_address.clone());
        contract.set_withdraw_fee(
            token_address.clone(),
            U128(50000),
            Some(U128(100)),
            Some(U128(200)),
        );
        let fee = contract.get_withdraw_fee(&token_address).unwrap();
        assert_eq!(
            U128(100),
            fee.lower_bound.unwrap(),
            "Lower bound not matched"
        );
        assert_eq!(
            U128(200),
            fee.upper_bound.unwrap(),
            "Upper bound not matched"
        );
    }

    #[test]
    #[should_panic]
    fn test_fee_setter_for_withdraw_with_unallowed_role() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(4);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: bob()); // bob is not allowed (has no role) to set deposit-fees;
        contract.set_withdraw_fee(
            token_address.clone(),
            U128(50000),
            Some(U128(100)),
            Some(U128(200)),
        );
        let fee = contract.get_withdraw_fee(&token_address).unwrap();
        assert_eq!(
            U128(100),
            fee.lower_bound.unwrap(),
            "Lower bound not matched"
        );
        assert_eq!(
            U128(200),
            fee.upper_bound.unwrap(),
            "Upper bound not matched"
        );
    }

    #[test]
    fn test_fee_token_percentage_for_deposit_fee() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(
            predecessor_account_id: fee_setter(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(token_address.clone());
        contract.set_deposit_fee(
            token_address.clone(),
            U128(50000),
            Some(U128(100)),
            Some(U128(200)),
        ); // 0.05%
        contract.set_deposit_fee_per_silo(
            silo_account(),
            Some(token_address.clone()),
            U128(20000),
            Some(U128(100)),
            Some(U128(200)),
        ); // 0.02%

        let expected_fee_percentage = contract
            .get_desposit_fee_per_silo(silo_account(), Some(token_address.clone()))
            .unwrap()
            .fee_percentage;
        assert_eq!(
            U128(20000),
            expected_fee_percentage,
            "Eth -> Aurora fee percentage not matched for deposit"
        );

        let expected_fee_percentage = contract
            .get_deposit_fee(&token_address)
            .unwrap()
            .fee_percentage;
        assert_eq!(
            U128(50000),
            expected_fee_percentage,
            "Eth -> Near fee percentage not matched for deposit"
        );
    }

    #[test]
    fn test_fee_token_percentage_setter_for_withdraw() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(
            predecessor_account_id: fee_setter(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(token_address.clone());
        contract.set_withdraw_fee(
            token_address.clone(),
            U128(90000),
            Some(U128(100)),
            Some(U128(200)),
        ); // 0.09%
        contract.set_withdraw_fee_per_silo(
            silo_account(),
            Some(token_address.clone()),
            U128(40000),
            Some(U128(100)),
            Some(U128(200)),
        ); // 0.04%
        let expected_fee_percentage = contract
            .get_withdraw_fee_per_silo(silo_account(), Some(token_address.clone()))
            .unwrap()
            .fee_percentage;
        assert_eq!(
            U128(40000),
            expected_fee_percentage,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );

        let expected_fee_percentage = contract
            .get_withdraw_fee(&token_address)
            .unwrap()
            .fee_percentage;
        assert_eq!(
            U128(90000),
            expected_fee_percentage,
            "Near -> Eth fee percentage not matched for withdraw"
        );
    }

    #[test]
    fn test_withdraw_fee_setter_silo() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());

        let withdraw_fee1 = Fee {
            fee_percentage: U128(100000),
            lower_bound: None,
            upper_bound: None,
        };
        contract.set_withdraw_fee_per_silo(
            silo_account(),
            Some(token_address.clone()),
            withdraw_fee1.fee_percentage,
            withdraw_fee1.lower_bound,
            withdraw_fee1.upper_bound,
        ); // 10% fee
        let expected_fee1 =
            contract.get_withdraw_fee_per_silo(silo_account(), Some(token_address.clone()));

        let withdraw_fee2 = Fee {
            fee_percentage: U128(200000),
            lower_bound: None,
            upper_bound: None,
        };
        contract.set_withdraw_fee_per_silo(
            silo_account(),
            Some(token_address.clone()),
            withdraw_fee2.fee_percentage,
            withdraw_fee2.lower_bound,
            withdraw_fee2.upper_bound,
        ); //20% fee
        let expected_fee2 = contract.get_withdraw_fee_per_silo(silo_account(), Some(token_address));

        assert_eq!(
            withdraw_fee1,
            expected_fee1.unwrap(),
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
        assert_eq!(
            withdraw_fee2,
            expected_fee2.unwrap(),
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
    }

    #[test]
    fn test_get_silo_with_token() {
        let _contract = BridgeTokenFactory::new(prover(), token_locker());
        let token_address = ethereum_address_from_id(1);
        let expected_key_with_token = get_silo_fee_map_key(&silo_account(), Some(&token_address));
        let expected_key_without_token = get_silo_fee_map_key(&silo_account(), None);
        assert_eq!(
            expected_key_with_token,
            format!("{}:{}", silo_account(), token_address.0),
            "Expected silo with token address not matched"
        );
        assert_eq!(
            expected_key_without_token,
            silo_account().to_string(),
            "Expected key without token is not matched"
        );
    }
    #[test]
    fn test_withdraw_fee_setter_silo_for_2_different_tokens() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token1_address = ethereum_address_from_id(1);
        let token2_address = ethereum_address_from_id(2);
        let token3_address = ethereum_address_from_id(3);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());

        let withdraw_fee_percentage1 = U128(100000);
        contract.set_withdraw_fee_per_silo(
            silo_account(),
            Some(token1_address.clone()),
            U128(100000),
            None,
            None,
        ); // 10% fee

        let withdraw_fee_percentage2 = U128(100000);
        contract.set_withdraw_fee_per_silo(
            silo_account(),
            Some(token2_address.clone()),
            U128(100000),
            None,
            None,
        ); //20% fee
        let expected_fee_percentage1 = contract
            .get_withdraw_fee_per_silo(silo_account(), Some(token1_address))
            .unwrap()
            .fee_percentage;
        let expected_fee_percentage2 = contract
            .get_withdraw_fee_per_silo(silo_account(), Some(token2_address))
            .unwrap()
            .fee_percentage;
        // for token-3 fee is not set
        let expected_fee_percentage3 =
            contract.get_withdraw_fee_per_silo(silo_account(), Some(token3_address));

        assert_eq!(
            withdraw_fee_percentage1, expected_fee_percentage1,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
        assert_eq!(
            withdraw_fee_percentage2, expected_fee_percentage2,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
        assert_eq!(
            expected_fee_percentage3, None,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
    }

    #[test]
    fn test_withdraw_fee_setter_silo_with_default_fee_and_per_token_fee() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());

        let withdraw_fee_percentage = U128(200000);
        contract.set_withdraw_fee_per_silo(
            silo_account(),
            Some(token_address.clone()),
            U128(200000),
            None,
            None,
        ); // 20% fee

        let default_withdraw_fee_percentage = U128(100000);
        contract.set_withdraw_fee_per_silo(silo_account(), None, U128(100000), None, None); // 10% fee
                                                                                            // Below token is not registered token therefore fees is default one's.

        let expected_fee_percentage = contract
            .get_withdraw_fee_per_silo(silo_account(), Some(token_address))
            .unwrap()
            .fee_percentage;
        let expected_default_fee_percentage = contract
            .get_withdraw_fee_per_silo(silo_account(), None)
            .unwrap()
            .fee_percentage;

        assert_eq!(
            withdraw_fee_percentage, expected_fee_percentage,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
        assert_eq!(
            default_withdraw_fee_percentage, expected_default_fee_percentage,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
    }

    #[test]
    fn test_withdraw_fee_setter_silo_without_default_fee_and_per_token_fee() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());

        let contract = BridgeTokenFactory::new(prover(), token_locker());

        let expected_fee_percentage = contract.get_withdraw_fee_per_silo(silo_account(), None);
        assert_eq!(
            expected_fee_percentage, None,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
    }
}
