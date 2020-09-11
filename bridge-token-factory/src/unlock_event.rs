use crate::prover::{EthAddress, EthEvent, EthEventParams};
use ethabi::{ParamType, Token};
use hex::ToHex;
use near_sdk::{AccountId, Balance};

/// Data that was emitted by the Ethereum Unlocked event.
#[derive(Debug, Eq, PartialEq)]
pub struct EthUnlockedEvent {
    pub locker_address: EthAddress,
    pub token: String,
    pub sender: String,
    pub amount: Balance,
    pub recipient: AccountId,
}

impl EthUnlockedEvent {
    fn event_params() -> EthEventParams {
        vec![
            ("token".to_string(), ParamType::String, false),
            ("sender".to_string(), ParamType::Address, true),
            ("amount".to_string(), ParamType::Uint(256), false),
            ("account_id".to_string(), ParamType::String, false),
        ]
    }

    /// Parse raw log entry data.
    pub fn from_log_entry_data(data: &[u8]) -> Self {
        let event =
            EthEvent::from_log_entry_data("Withdraw", EthUnlockedEvent::event_params(), data);
        let token = event.log.params[0].value.clone().to_string().unwrap();
        let sender = event.log.params[1].value.clone().to_address().unwrap().0;
        let sender = (&sender).encode_hex::<String>();
        let amount = event.log.params[2]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u128();
        let recipient = event.log.params[3].value.clone().to_string().unwrap();
        Self {
            locker_address: event.locker_address,
            token,
            sender,
            amount,
            recipient,
        }
    }

    pub fn to_log_entry_data(&self) -> Vec<u8> {
        EthEvent::to_log_entry_data(
            "Withdraw",
            EthUnlockedEvent::event_params(),
            self.locker_address,
            vec![hex::decode(self.sender.clone()).unwrap()],
            vec![
                Token::String(self.token.clone()),
                Token::Uint(self.amount.into()),
                Token::String(self.recipient.clone()),
            ],
        )
    }
}

impl std::fmt::Display for EthUnlockedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token: {}; sender: {}; amount: {}; recipient: {}",
            self.token, self.sender, self.amount, self.recipient
        )
    }
}
