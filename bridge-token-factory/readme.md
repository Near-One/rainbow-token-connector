# Bridge-Token-Factory

## Fee Integration for deposit and withdrawal of tokens

**NOTE**:

1. To set fee-percentage and fee-bounds caller (predecessor) must have `FeeSetter` role.
2. Fee-percentage has **6-decimal** precision for eg. to set deposit fee percentage as 10%, value for function param is 0.1 \* 10^6 ie. 10^5.

- ### For deposit:

  - `set_deposit_fee`: method to set deposit fee for eth -> near and eth -> aurora.
  - `set_deposit_fee_per_silo`: method to set deposit fee for different aurora-silos per different tokens.
  - `unset_deposit_fee`: method to unset deposit fee for eth -> near and eth -> aurora.
  - `unset_deposit_fee_per_silo`: method to unset deposit fee for different aurora-silos per different tokens.
  - `get_deposit_fee`: returns deposit token fee for specific erc-20 token address passed.
  - `get_deposit_fee_per_silo`: returns deposit fee for different silos per different tokens. It also returns the default value, if have any.

- ### For withdraw:

  - `set_withdraw_fee`: method to set withdraw fee for near -> eth and aurora -> eth.
  - `set_withdraw_fee_per_silo`: method to set withdraw fee for different aurora-silos per different tokens.
  - `unset_withdraw_fee`: method to unset withdraw fee for near -> eth and aurora -> eth.
  - `unset_withdraw_fee_per_silo`: method to unset withdraw fee for different aurora-silos per different tokens.
  - `get_withdraw_token_fee`: returns withdraw fee for specific erc-20 token address.
  - `get_withdraw_fee_per_silo`: returns withdraw fee-percentage for different silos per different tokens. It also returns the default value, if have any.

- ### To claim the accumulated fee:-
  - `claim_fee`: method to claim the fee-amount accumulated, by passing Near-token-address and the desired amount.
    **NOTE**: To claim fee caller or predecessor must have access-role:`FeeClaimer`
