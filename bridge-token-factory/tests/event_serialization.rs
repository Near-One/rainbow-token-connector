use std::fs;

use bridge_token_factory::EthLockedEvent;
use serde::{Deserialize, Serialize};

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
        assert_eq!(locked_event.recipient, event.recipient);

        let re_serialize = locked_event.to_log_entry_data();
        assert_eq!(re_serialize, serialized);
    }
}
