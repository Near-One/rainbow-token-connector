use near_sdk::AccountId;

pub mod prover;
pub mod result_types;

pub struct Recipient {
    pub target: AccountId,
    pub message: Option<String>,
}

/// `recipient` is the target account id receiving current ERC-20 tokens.
///
/// If `recipient` doesn't contain a semicolon (:) then it is interpreted as a NEAR account id
/// and token are minted as NEP-141 directly on `recipient` account id.
///
/// Otherwise, the format expected is: <target_address>:<message>
///
/// @target_address: Account id of the contract to transfer current funds
/// @message: Free form message to be send to the target using ft_transfer_call
///
/// The final message sent to the `target_address` has the format:
///
/// <message>
///
/// Where `message` is the free form string that was passed.
pub fn parse_recipient(recipient: String) -> Recipient {
    if recipient.contains(':') {
        let mut iter = recipient.split(':');
        let target = iter.next().unwrap().parse().unwrap();
        let message = iter.collect::<Vec<&str>>().join(":");

        Recipient {
            target,
            message: Some(message),
        }
    } else {
        Recipient {
            target: recipient.parse().unwrap(),
            message: None,
        }
    }
}
