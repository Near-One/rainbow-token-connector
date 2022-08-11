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
    (0..rng.gen::<u8>())
        .map(|_| (0x20u8 + (rng.gen::<f32>() * 96.0) as u8) as char)
        .collect()
}

fn generate_random_eth_locked_event(rng: &mut ThreadRng) -> EthLockedEvent {
    EthLockedEvent {
        locker_address: rng.gen::<[u8; 20]>(),
        token: hex::encode(rng.gen::<[u8; 20]>()),
        sender: hex::encode(rng.gen::<[u8; 20]>()),
        amount: rng.gen::<u128>(),
        recipient: rand_string(rng).parse().unwrap(),
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
