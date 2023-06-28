# Bridge-Token-Factory
---
## Fee Integration for deposit and withdrawal of tokens
**NOTE**:
1. To set fee-percentage and fee-bounds caller (predecessor) must have `FeeSetter` role.
2. Fee-percentage has **6-decimal** precision for eg. to set deposit fee percentage as 10%, value for function param is 0.1 * 10^6 ie. 10^5.

* ### For deposit: 
  
  * `set_deposit_fee_percentage`: method to set deposit fee-percentage for eth -> near and eth -> aurora.
  * `set_deposit_fee_bound`: method to set upper and lower_bounds for deposit fee.
  * `get_deposit_token_fee_percentage`: returns deposit token fee percentage for specific erc-20 token address passed.
  * `get_deposit_token_fee_bound`: returns fee-bounds for deposits of specific erc-20 token address.


* ### For withdraw:
  
  * `set_withdraw_fee_percentage`: method to set withdraw fee-percentage for near -> eth and aurora -> eth.
  * `set_withdraw_fee_percentage_for_token_per_silo`: method to set withdraw fee-percentage for different aurora-silos per different tokens. Here first it checks for any default value set for the silo or not, than it updates the passed params fee-percentage values. 
  * `set_default_withdraw_fee_percentage_per_silo`: method to set default fee-percentage for different aurora-silos per different tokens.
  * `set_withdraw_fee_bound`: method to set upper and lower_bounds for withdraw fee.
  * `get_withdraw_token_fee_percentage`: returns withdraw fee-percentage for specific erc-20 token address.
  * `get_withdraw_token_fee_bound`: returns fee-bounds for withdraw of specific erc-20 token address.
  * `get_withdraw_fee_percentage_per_silo_per_token`: returns withdraw fee-percentage for different silos per different tokens. It also returns the default value, if have any.
  
* ### To claim the accumulated fee:-
   * `claim_fee`: method to claim the fee-amount accumulated, by passing Near-token-address and the desired amount. 
  **NOTE**: To claim fee caller or predecessor must have access-role:`FeeClaimer`
     
