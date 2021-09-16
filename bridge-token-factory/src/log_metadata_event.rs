use crate::prover::{EthAddress, EthEvent, EthEventParams};
use ethabi::{ParamType, Token};
use hex::ToHex;

/// Data that was emitted by the Ethereum Locked event.
#[derive(Debug, Eq, PartialEq)]
pub struct TokenMetadataEvent {
    pub metadata_connector: EthAddress,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub timestamp: u64,
}

impl TokenMetadataEvent {
    fn event_params() -> EthEventParams {
        vec![
            ("token".to_string(), ParamType::Address, true),
            ("name".to_string(), ParamType::String, false),
            ("symbol".to_string(), ParamType::String, false),
            ("decimals".to_string(), ParamType::Uint(8), false),
            ("timestamp".to_string(), ParamType::Uint(64), false),
        ]
    }

    /// Parse raw log entry data.
    pub fn from_log_entry_data(data: &[u8]) -> Self {
        let event = EthEvent::from_log_entry_data("Log", TokenMetadataEvent::event_params(), data);
        let token = event.log.params[0].value.clone().to_address().unwrap().0;
        let token = (&token).encode_hex::<String>();
        let name = event.log.params[1].value.clone().to_string().unwrap();
        let symbol = event.log.params[2].value.clone().to_string().unwrap();
        let decimals = event.log.params[3]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_usize() as u8;
        let timestamp = event.log.params[4]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_usize() as u64;

        Self {
            metadata_connector: event.locker_address,
            token,
            name,
            symbol,
            decimals,
            timestamp,
        }
    }

    pub fn to_log_entry_data(&self) -> Vec<u8> {
        EthEvent::to_log_entry_data(
            "Log",
            TokenMetadataEvent::event_params(),
            self.metadata_connector,
            vec![hex::decode(self.token.clone()).unwrap()],
            vec![
                Token::String(self.name.clone()),
                Token::String(self.symbol.clone()),
                Token::Uint(self.decimals.into()),
                Token::Uint(self.timestamp.into()),
            ],
        )
    }
}

impl std::fmt::Display for TokenMetadataEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token: {}; name: {}; symbol: {}; decimals: {}",
            self.token, self.name, self.symbol, self.decimals
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_metadata_data() {
        let event_data = TokenMetadataEvent {
            metadata_connector: [0u8; 20],
            token: "6b175474e89094c44da98b954eedeac495271d0f".to_string(),
            name: "TEST".to_string(),
            symbol: "TST".to_string(),
            decimals: 18,
            timestamp: 13042194,
        };
        let data = event_data.to_log_entry_data();
        let result = TokenMetadataEvent::from_log_entry_data(&data);
        assert_eq!(result, event_data);
    }
}
