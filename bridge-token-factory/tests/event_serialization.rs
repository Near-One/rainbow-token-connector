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

fn rand_string(rng: &mut ThreadRng) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._-";
    let string_len = rng.gen_range(2, 64);

    'main: loop {
        let rand_str: String = (0..string_len)
            .map(|_| {
                let idx = rng.gen_range(0, CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        let mut last_char_is_separator = true;

        for c in rand_str.chars() {
            let current_char_is_separator = match c {
                '-' | '_' | '.' => true,
                _ => false,
            };

            if current_char_is_separator && last_char_is_separator {
                continue 'main;
            }

            last_char_is_separator = current_char_is_separator;
        }

        if !last_char_is_separator {
            return rand_str;
        }
    }
}

fn generate_random_eth_locked_event(rng: &mut ThreadRng) -> EthLockedEvent {
    let rand_str = rand_string(rng);

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