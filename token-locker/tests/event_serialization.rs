use std::fs;

use serde::{Deserialize, Serialize};

use rand::prelude::ThreadRng;
use rand::Rng;
use token_locker::EthUnlockedEvent;

fn generate_random_eth_unlocked_event(rng: &mut ThreadRng) -> EthUnlockedEvent {
    EthUnlockedEvent {
        locker_address: rng.gen::<[u8; 20]>(),
        token: hex::encode(rng.gen::<[u8; 20]>()),
        sender: hex::encode(rng.gen::<[u8; 20]>()),
        amount: rng.gen::<u128>(),
        recipient: rand_string(rng),
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
