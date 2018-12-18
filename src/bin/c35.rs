extern crate common;
extern crate rand;
extern crate ramp;

use ramp::Int;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use common::dh::{gen_dh_pair, gen_session_key, P, G};
use common::sha1::sha1_digest;
use common::crypto_helper::{encrypt_cbc, decrypt_cbc, BLOCK_SIZE};
use common::util::{random_bytes, print_hex};
use common::pkcs7::{pkcs7_pad, pkcs7_strip};

enum Msg {
    InitParams {
        p: Int,
        g: Int,
    },
    Ack,
    InitA {
        a_pub: Int,
    },
    InitB {
        b_pub: Int,
    },
    Echo {
        iv: Vec<u8>,
        msg: Vec<u8>
    }
}

fn node_a(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let (pub_key, priv_key) = gen_dh_pair(&P, &G);
    let mut aes_key = None;
    let secret_msg = b"Super secret message";

    tx.send(Msg::InitParams { p: P.clone(), g: G.clone() }).unwrap();

    loop {
        match rx.recv().unwrap() {
            Msg::Ack => {
                tx.send(Msg::InitA { a_pub: pub_key.clone() });
            }
            Msg::InitB { b_pub } => {
                let s = gen_session_key(&b_pub, &priv_key, &P);
                println!("s a = {}", s);
                let s_str = s.to_str_radix(16, false);
                let s_hash = sha1_digest(&s_str.as_bytes());

                aes_key = Some((&s_hash[..BLOCK_SIZE]).to_vec());

                let new_iv = random_bytes(BLOCK_SIZE);
                let new_ct = encrypt_cbc(&aes_key.as_ref().unwrap(), &new_iv, &pkcs7_pad(secret_msg, BLOCK_SIZE));

                tx.send(Msg::Echo { iv: new_iv, msg: new_ct }).unwrap();
            },
            Msg::Echo { iv, msg } => {
                let pt = decrypt_cbc(&aes_key.as_ref().unwrap(), &iv, &msg);

                println!("Echo A:");
                print_hex(&pt);

                assert_eq!(&pkcs7_strip(&pt, BLOCK_SIZE).unwrap(), &secret_msg);

                break;
            },
            _ => panic!("Unexpected message at node A"),
        }
    }
}

fn node_b(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let mut remote_p = None;
    let mut remote_g = None;

    loop {
        match rx.recv().unwrap() {
            Msg::InitParams { p, g } => {
                remote_p = Some(p);
                remote_g = Some(g);

                tx.send(Msg::Ack).unwrap();
            },
            Msg::InitA { .. } => {
                let (pub_key, _) = gen_dh_pair(
                    &remote_p.as_ref().unwrap(),
                    &remote_g.as_ref().unwrap());

                println!("B pub: {}", pub_key);
                tx.send(Msg::InitB { b_pub: pub_key }).unwrap();

                break;
            },

            Msg::Echo { .. } => {
                // Would normally decrypt and verify the message here
                // but due to the bogus g parameter it will definitely fail.
                // This could be worked around by modifying the public key but that's
                // not part of the challenge.

            },
            _ => panic!("Unexpected message at node B"),
        };
    }
}

fn mitm(tx_a: Sender<Msg>, tx_b: Sender<Msg>, rx_a: Receiver<Msg>, rx_b: Receiver<Msg>, evil_g: Int) {

    let mut saved_b_pub: Option<Int> = None;

    loop {
        match rx_a.recv().unwrap() {
            Msg::InitParams { p, .. } => {
                tx_b.send(Msg::InitParams { p, g: evil_g.clone() }).unwrap();
            },
            Msg::InitA { a_pub } => {
                tx_b.send(Msg::InitA { a_pub });
            }
            Msg::Echo { iv, msg } => {
                // g = 1 => B = 1
                // g = p => B = 0
                // For the above two cases calculating two values is unnecessary
                // but the code is simpler if we don't special case them.
                //
                // g = p - 1 => B = 1 or B = p - 1
                // Calculate the session key for both even and odd private key
                // values since we don't know A's private key but we can
                // calculate the only two session key values that result.
                let mut s_values: Vec<Int> = (1..3).map(
                    |fake_priv| saved_b_pub.as_ref()
                        .unwrap()
                        .pow_mod(&Int::from(fake_priv), &P))
                    .collect();
                s_values.dedup();

                for s_val in s_values.iter() {
                    let s_str = s_val.to_str_radix(16, false);
                    let s_hash = sha1_digest(&s_str.as_bytes());
                    let pt = decrypt_cbc(&s_hash[..BLOCK_SIZE], &iv, &msg);

                    println!("MITM A->B decrypt (s_val {}):", s_val);
                    print_hex(&pt);
                }
                
                tx_a.send(Msg::Echo { iv, msg }).unwrap();

                break;
            },
            _ => panic!("Unexpected message at node B"),
        }

        match rx_b.recv().unwrap() {
            Msg::Ack => {
                tx_a.send(Msg::Ack).unwrap();
            },
            Msg::InitB { b_pub } => {
                saved_b_pub = Some(b_pub.clone());
                tx_a.send(Msg::InitB { b_pub }).unwrap();
            },
            _ => panic!("Unexpected message at node B"),
        }
    }
}

fn main() {
    // Part 2: MITM modifying messages and decrypting communication
    let evil_g_values = [Int::from(1), P.clone(), P.clone() - 1];

    for evil_g in evil_g_values.iter().cloned() {
        let (a_tx, ma_rx) = mpsc::channel();
        let (ma_tx, a_rx) = mpsc::channel();
        let (b_tx, mb_rx) = mpsc::channel();
        let (mb_tx, b_rx) = mpsc::channel();

        // A
        let a = thread::spawn(move || node_a(a_tx, a_rx));

        // B
        let b = thread::spawn(move || node_b(b_tx, b_rx));

        // MITM
        let m = thread::spawn(move || mitm(ma_tx, mb_tx, ma_rx, mb_rx, evil_g));

        a.join().unwrap();
        b.join().unwrap();
        m.join().unwrap();
    }
}