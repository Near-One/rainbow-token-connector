NETWORK=mainnet_aurora
CONFIG_NAME="aurora-mainnet"

AURORA_TOKEN_ADDRESS="0xb12bfca5a55806aaf64e99521918a4bf0fc40802"

RECEIVER_ID="silo-1.aurora-silo-dev.near"
AMOUNT="100000"
MSG=""

deploy:
	yarn hardhat deploy --silo $(CONFIG_NAME) --network $(NETWORK)

upgrade:
	yarn hardhat upgrade --silo $(CONFIG_NAME) --network $(NETWORK)

register_token:
	yarn hardhat register_token --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --network $(NETWORK)

get_token_near_account_id:
	yarn hardhat get_token_near_account_id --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --network $(NETWORK)

storage_deposit:
	yarn hardhat storage_deposit --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --network $(NETWORK)

is_storage_registered:
	yarn hardhat is_storage_registered --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --network $(NETWORK)

safe_ft_transfer_call_to_near:
	yarn hardhat safe_ft_transfer_call_to_near --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --receiver-id $(RECEIVER_ID) --amount $(AMOUNT) --msg $(MSG) --network $(NETWORK)

ft_transfer_call_to_near:
	yarn hardhat ft_transfer_call_to_near --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --receiver-id $(RECEIVER_ID) --amount $(AMOUNT) --msg $(MSG) --network $(NETWORK)

recipient_storage_deposit:
	yarn hardhat recipient_storage_deposit --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --receiver-id $(RECEIVER_ID) --network $(NETWORK)

is_recipient_storage_registered:
	yarn hardhat is_recipient_storage_registered --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --receiver-id $(RECEIVER_ID) --network $(NETWORK)

get_user_balance:
	yarn hardhat get_user_balance --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --network $(NETWORK)

withdraw:
	yarn hardhat withdraw --silo $(CONFIG_NAME) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --network $(NETWORK)

deploySDK:
	yarn hardhat deploy-sdk --network $(NETWORK)
