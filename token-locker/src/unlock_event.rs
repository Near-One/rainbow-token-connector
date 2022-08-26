use bridge_common::prover::{EthAddress, EthEvent, EthEventParams};
use ethabi::{ParamType, Token};
use hex::ToHex;
use near_sdk::{AccountId, Balance};

/// Data that was emitted by the Ethereum Unlocked event.
#[derive(Debug, Eq, PartialEq)]
pub struct EthUnlockedEvent {
    pub eth_factory_address: EthAddress,
    pub token: String,
    pub sender: String,
    pub amount: Balance,
    pub recipient: AccountId,
    pub token_eth_address: EthAddress,
}

impl EthUnlockedEvent {
    fn event_params() -> EthEventParams {
        vec![
            ("token".to_string(), ParamType::String, false),
            ("sender".to_string(), ParamType::Address, true),
            ("amount".to_string(), ParamType::Uint(256), false),
            ("recipient".to_string(), ParamType::String, false),
            ("tokenEthAddress".to_string(), ParamType::Address, true),
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
        let token_eth_address = event.log.params[4].value.clone().to_address().unwrap().0;
        Self {
            eth_factory_address: event.locker_address,
            token,
            sender,
            amount,
            recipient: recipient.parse().unwrap(),
            token_eth_address,
        }
    }

    #[warn(dead_code)]
    pub fn to_log_entry_data(&self) -> Vec<u8> {
        EthEvent::to_log_entry_data(
            "Withdraw",
            EthUnlockedEvent::event_params(),
            self.eth_factory_address,
            vec![
                hex::decode(self.sender.clone()).unwrap(),
                self.token_eth_address.to_vec(),
            ],
            vec![
                Token::String(self.token.clone()),
                Token::Uint(self.amount.into()),
                Token::String(self.recipient.clone().into()),
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

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::EthUnlockedEvent;
    use rand::prelude::ThreadRng;
    use rand::Rng;

    fn generate_random_eth_unlocked_event(rng: &mut ThreadRng) -> EthUnlockedEvent {
        EthUnlockedEvent {
            eth_factory_address: rng.gen::<[u8; 20]>(),
            token: hex::encode(rng.gen::<[u8; 20]>()),
            sender: hex::encode(rng.gen::<[u8; 20]>()),
            amount: rng.gen::<u128>(),
            recipient: "some_recipient.near".parse().unwrap(),
            token_eth_address: rng.gen::<[u8; 20]>(),
        }
    }

    #[test]
    fn fuzzing_eth_unlocked() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let event = generate_random_eth_unlocked_event(&mut rng);
            let serialized = event.to_log_entry_data();
            let deserialized = EthUnlockedEvent::from_log_entry_data(serialized.as_ref());
            assert_eq!(event, deserialized);
        }
    }
}
