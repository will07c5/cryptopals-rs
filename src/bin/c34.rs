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
    InitA {
        p: Int,
        g: Int,
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

    tx.send(Msg::InitA { p: P.clone(), g: G.clone(), a_pub: pub_key }).unwrap();

    loop {
        match rx.recv().unwrap() {
            Msg::InitB { b_pub }=> {
                let s = gen_session_key(&b_pub, &priv_key, &P);
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
            }
            _ => panic!("Unexpected message at node A"),
        }
    }
}

fn node_b(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let mut priv_key = None;
    let mut remote_pub = None;
    let mut remote_p = None;

    loop {
        match rx.recv().unwrap() {
            Msg::InitA { p, g, a_pub } => {
                let pair = gen_dh_pair(&p, &g);
                priv_key = Some(pair.1);
                remote_pub = Some(a_pub);
                remote_p = Some(p);

                tx.send(Msg::InitB { b_pub: pair.0 }).unwrap();
            },
            Msg::Echo { iv, msg } => {
                let s = gen_session_key(
                    &remote_pub.unwrap(),
                    &priv_key.unwrap(),
                    &remote_p.unwrap());
                let s_str = s.to_str_radix(16, false);
                let s_hash = sha1_digest(&s_str.as_bytes());

                let pt = decrypt_cbc(&s_hash[..BLOCK_SIZE], &iv, &msg);

                println!("Echo B:");
                print_hex(&pt);

                let new_iv = random_bytes(BLOCK_SIZE);
                let new_ct = encrypt_cbc(&s_hash[..BLOCK_SIZE], &new_iv, &pt);

                tx.send(Msg::Echo { iv: new_iv, msg: new_ct }).unwrap();

                break;
            },
            _ => panic!("Unexpected message at node B"),
        };
    }
}

fn mitm(tx_a: Sender<Msg>, tx_b: Sender<Msg>, rx_a: Receiver<Msg>, rx_b: Receiver<Msg>) {
    let s_str = "0";
    let s_hash = sha1_digest(&s_str.as_bytes());
    let mut remote_p = None;

    loop {
        match rx_a.recv().unwrap() {
            Msg::InitA { p, g, a_pub: _ } => {
                tx_b.send(Msg::InitA { p: p.clone(), g, a_pub: p.clone() }).unwrap();
                remote_p = Some(p);
            },
            Msg::Echo { iv, msg } => {
                let pt = decrypt_cbc(&s_hash[..BLOCK_SIZE], &iv, &msg);

                println!("MITM A->B decrypt:");
                print_hex(&pt);

                tx_b.send(Msg::Echo { iv, msg });
            },
            _ => panic!("Unexpected message at node B"),
        }

        match rx_b.recv().unwrap() {
            Msg::InitB { b_pub: _ } => {
                tx_a.send(Msg::InitB { b_pub: remote_p.as_ref().unwrap().clone() }).unwrap();
            },
            Msg::Echo { iv, msg } => {
                let pt = decrypt_cbc(&s_hash[..BLOCK_SIZE], &iv, &msg);

                println!("MITM B->A decrypt:");
                print_hex(&pt);

                tx_a.send(Msg::Echo { iv, msg });

                break;
            },
            _ => panic!("Unexpected message at node B"),
        }
    }
}

fn main() {
    // Part 1: Verify communication with no MITM
    {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();

        // A
        let a = thread::spawn(move || node_a(a_tx, a_rx));

        // B
        let b = thread::spawn(move || node_b(b_tx, b_rx));

        a.join().unwrap();
        b.join().unwrap();
    }

    // Part 2: MITM modifying messages and decrypting communication
    {
        let (a_tx, ma_rx) = mpsc::channel();
        let (ma_tx, a_rx) = mpsc::channel();
        let (b_tx, mb_rx) = mpsc::channel();
        let (mb_tx, b_rx) = mpsc::channel();

        // A
        let a = thread::spawn(move || node_a(a_tx, a_rx));

        // B
        let b = thread::spawn(move || node_b(b_tx, b_rx));

        // MITM
        let m = thread::spawn(move || mitm(ma_tx, mb_tx, ma_rx, mb_rx));

        a.join().unwrap();
        b.join().unwrap();
        m.join().unwrap();
    }
}