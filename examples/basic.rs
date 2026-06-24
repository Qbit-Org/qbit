use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify,
};
use std::time::Instant;

fn main() {
    println!("Bitcoin PQC Library Example");
    println!("==========================\n");
    println!("This example tests the single SLH-DSA-SHA2-128s-bounded30 profile.\n");

    let mut random_data = vec![0u8; 128];
    if let Err(e) = getrandom::fill(&mut random_data) {
        println!("Error collecting entropy: {e}");
        return;
    }

    println!("Profile: SLH-DSA-SHA2-128s-bounded30");
    println!("------------------------------------");
    println!("Public key size: {} bytes", public_key_size());
    println!("Secret key size: {} bytes", secret_key_size());
    println!("Signature size: {} bytes", signature_size());

    let start = Instant::now();
    let keypair = match generate_keypair(&random_data) {
        Ok(kp) => kp,
        Err(e) => {
            println!("Error generating key pair: {e}");
            return;
        }
    };
    println!("Key generation time: {:?}", start.elapsed());

    let message = b"This is a test message for PQC signature verification";

    let start = Instant::now();
    let signature = match sign(&keypair.secret_key, message) {
        Ok(sig) => sig,
        Err(e) => {
            println!("Error signing message: {e}");
            return;
        }
    };
    println!("Signing time: {:?}", start.elapsed());
    println!("Actual signature size: {} bytes", signature.bytes.len());

    let start = Instant::now();
    match verify(&keypair.public_key, message, &signature) {
        Ok(()) => println!("Signature verified successfully!"),
        Err(e) => println!("Signature verification failed: {e}"),
    }
    println!("Verification time: {:?}", start.elapsed());

    let modified_message = b"This is a MODIFIED message for PQC signature verification";
    match verify(&keypair.public_key, modified_message, &signature) {
        Ok(()) => println!("ERROR: Signature verified for modified message!"),
        Err(_) => println!("Correctly rejected signature for modified message"),
    }
}
