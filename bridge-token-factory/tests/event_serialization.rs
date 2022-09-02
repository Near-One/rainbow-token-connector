use std::fs;

use rand::prelude::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};

use bridge_token_factory::EthLockedEvent;

#[derive(Serialize, Deserialize, Debug)]
struct PartialLockedEvent {
    serialized: String,
    amount: u128,
    recipient: String,
}

#[test]
#[ignore]
fn real_data_locked_event_serialization() {
    let content = fs::read_to_string("res/locked_events.json")
        .expect("Something went wrong reading the file");

    let events: Vec<PartialLockedEvent> =
        serde_json::from_str(content.as_str()).expect("Fail parsing json");

    for event in events {
        let serialized = hex::decode(event.serialized).expect("Invalid hex encoded event");
        let locked_event = EthLockedEvent::from_log_entry_data(serialized.as_ref());

        assert_eq!(locked_event.amount, event.amount);
        assert_eq!(locked_event.recipient.to_string(), event.recipient);

        let re_serialize = locked_event.to_log_entry_data();
        assert_eq!(re_serialize, serialized);
    }
}

fn generate_random_near_account_id(rng: &mut ThreadRng) -> String {
    const CHARSET_WITHOUT_SEPARATORS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._-";
    let string_len = rng.gen_range(2, 64);
    
    let mut gen_rand_char = |use_separators: bool| -> char {
        let charset = if use_separators {
            CHARSET
        } else {
            CHARSET_WITHOUT_SEPARATORS
        };
        let idx = rng.gen_range(0, charset.len());
        charset[idx] as char
    };
    
    let is_separator_char = |c: char| -> bool { matches!(c, '-' | '_' | '.') };
    
    let mut is_last_char_separator = true;
    let mut rand_str: String = (0..string_len)
        .map(|_| {
            let rand_char = gen_rand_char(!is_last_char_separator);
            is_last_char_separator = is_separator_char(rand_char);
            rand_char
        })
        .collect();

    // Make last element non-separator
    if is_last_char_separator {
        rand_str.pop();
        rand_str.push(gen_rand_char(false));
    }
    
    rand_str
}

fn generate_random_eth_locked_event(rng: &mut ThreadRng) -> EthLockedEvent {
    let rand_str = generate_random_near_account_id(rng);

    EthLockedEvent {
        locker_address: rng.gen::<[u8; 20]>(),
        token: hex::encode(rng.gen::<[u8; 20]>()),
        sender: hex::encode(rng.gen::<[u8; 20]>()),
        amount: rng.gen::<u128>(),
        recipient: rand_str.parse().unwrap(),
    }
}

#[test]
fn fuzzing_eth_locked() {
    let mut rng = rand::thread_rng();
    for _ in 0..1000 {
        let event = generate_random_eth_locked_event(&mut rng);
        let serialized = event.to_log_entry_data();
        let deserialized = EthLockedEvent::from_log_entry_data(serialized.as_ref());
        assert_eq!(event, deserialized);
    }
}
