use std::fmt;
use std::str::FromStr;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Debug, Clone, PartialEq)]
pub struct EthAddressHex(pub String);

impl<'de> Deserialize<'de> for EthAddressHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        EthAddressHex::from_str(&s).map_err(|e| serde::de::Error::custom(e.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEthAddressError(String);

impl fmt::Display for ParseEthAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The hex eth address is invalid")
    }
}

impl FromStr for EthAddressHex {
    type Err = ParseEthAddressError;
    fn from_str(s: &str) -> Result<EthAddressHex, Self::Err> {
        let s = if s.starts_with("0x") {
            s[2..].to_lowercase()
        } else {
            s.to_lowercase()
        };

        if !is_hex_string(&s) {
            return Err(ParseEthAddressError("Invalid hex character".to_owned()));
        }
        if s.len() != 40 {
            return Err(ParseEthAddressError(
                "Address should be 20 bytes long".to_owned(),
            ));
        }

        Ok(EthAddressHex(s))
    }
}

fn is_hex_string(hex_str: &str) -> bool {
    for c in hex_str.chars() {
        if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fee {
    pub fee_percentage: U128,
    pub lower_bound: Option<U128>,
    pub upper_bound: Option<U128>,
}

pub trait SdkUnwrap<T> {
    fn sdk_unwrap(self) -> T;
}

impl<T> SdkUnwrap<T> for Option<T> {
    fn sdk_unwrap(self) -> T {
        self.unwrap_or_else(|| near_sdk::env::panic_str("ERR_UNWRAP"))
    }
}

impl<T, E: AsRef<[u8]>> SdkUnwrap<T> for Result<T, E> {
    fn sdk_unwrap(self) -> T {
        self.unwrap_or_else(|e| near_sdk::env::panic_str(err_to_str(&e)))
    }
}

fn err_to_str<E: AsRef<[u8]>>(err: &E) -> &str {
    std::str::from_utf8(err.as_ref()).unwrap_or("INVALID_UTF8_ERR_STRING")
}
