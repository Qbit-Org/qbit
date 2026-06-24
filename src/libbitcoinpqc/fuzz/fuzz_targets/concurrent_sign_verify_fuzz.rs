#![no_main]

use std::sync::OnceLock;
use std::thread;

use bitcoinpqc::{generate_keypair, sign, verify, KeyPair};
use libfuzzer_sys::fuzz_target;

const KEYGEN_SEED: [u8; 128] = [0xC7; 128];

fn fixed_keypair() -> &'static KeyPair {
    static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();
    KEYPAIR.get_or_init(|| generate_keypair(&KEYGEN_SEED).expect("fixed keypair generation failed"))
}

fn message_len(selector: u8) -> usize {
    match selector % 6 {
        0 => 0,
        1 => 1,
        2 => 32,
        3 => 255,
        4 => 1024,
        _ => 4096,
    }
}

fn build_messages(data: &[u8]) -> Vec<Vec<u8>> {
    let thread_count = 2 + (data.first().copied().unwrap_or(0) as usize % 3);
    let body = data.get(1..).unwrap_or(&[]);

    (0..thread_count)
        .map(|thread_index| {
            let selector = body
                .get(thread_index)
                .copied()
                .unwrap_or(thread_index as u8);
            let len = message_len(selector);

            if body.is_empty() {
                vec![selector; len]
            } else {
                (0..len)
                    .map(|i| {
                        body[(i + thread_index) % body.len()]
                            .wrapping_add((thread_index as u8).wrapping_mul(17))
                            .wrapping_add(i as u8)
                    })
                    .collect()
            }
        })
        .collect()
}

fn mutated_message(message: &[u8], selector: u8) -> Vec<u8> {
    let mut mutated = message.to_vec();
    if mutated.is_empty() {
        mutated.push(selector | 1);
    } else {
        let index = selector as usize % mutated.len();
        let mask = 1u8 << (selector & 0x07);
        mutated[index] ^= mask;
    }
    mutated
}

fuzz_target!(|data: &[u8]| {
    let keypair = fixed_keypair();
    let messages = build_messages(data);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(messages.len());
        for (index, message) in messages.iter().enumerate() {
            handles.push(scope.spawn(move || {
                let signature = sign(&keypair.secret_key, message).expect("concurrent sign failed");
                verify(&keypair.public_key, message, &signature).expect("concurrent verify failed");

                let selector = data.get(index).copied().unwrap_or(index as u8);
                let mutated = mutated_message(message, selector);
                assert!(
                    verify(&keypair.public_key, &mutated, &signature).is_err(),
                    "signature verified for a concurrently mutated message"
                );
            }));
        }

        for handle in handles {
            handle.join().expect("sign/verify worker panicked");
        }
    });
});
