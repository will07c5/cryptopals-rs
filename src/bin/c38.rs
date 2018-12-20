extern crate common;
extern crate rand;
extern crate ramp;
extern crate hex;
extern crate crypto;

use ramp::Int;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use common::dh::{gen_dh_pair, P, G};
use common::util::random_bytes;
use rand::Rng;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

enum Msg {
    EmailPubKey {
        email: Vec<u8>,
        a_pub: Int,
    },
    SaltPubKey {
        salt: Vec<u8>,
        b_pub: Int,
        u: Int,
    },
    Check {
        client_check: Vec<u8>
    },
    BadEmailOrPW,
    PWAccepted,
}

const PASSWORD: &[u8] = b"ab";
const EMAIL: &[u8] = b"foo@example.com";

fn combine_salt_pw(salt: &[u8], pw: &[u8]) -> Int {
    let mut hasher = Sha256::new();
    hasher.input(&salt);
    hasher.input(&pw);

    let mut x_h = vec![0u8; hasher.output_bytes()];
    hasher.result(&mut x_h);
    // there's probably a less stupid way to do this but this works for now
    Int::from_str_radix(&hex::encode(&x_h), 16).unwrap()
}

fn digest_ramp_int(val: &Int) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(&val.to_str_radix(16, false).as_bytes());

    let mut x_h = vec![0u8; hasher.output_bytes()];
    hasher.result(&mut x_h);

    x_h
}

fn client_node(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let (pub_key, priv_key) = gen_dh_pair(&P, &G);

    tx.send(Msg::EmailPubKey { email: EMAIL.to_vec(), a_pub: pub_key.clone() }).unwrap();

    loop {
        let msg = rx.recv().unwrap();

        match msg {
            Msg::SaltPubKey { salt, b_pub, u } => {
                let x = combine_salt_pw(&salt, &PASSWORD);

                println!("a {}", priv_key);
                println!("A {}", pub_key);
                println!("u {}", u);
                println!("x {}", x);
                println!("N {}", *P);
                let check_val = b_pub.pow_mod(&(&priv_key + u*x), &P); 
                println!("Ka {}", check_val);
                let check_digest = digest_ramp_int(&check_val);

                tx.send(Msg::Check { client_check: check_digest }).unwrap();
            },
            Msg::PWAccepted => {
                println!("Password accepted!");
                break;
            },
            Msg::BadEmailOrPW => {
                println!("Password failed to validate");
                break;
            },
            _ => panic!("Unexpected message"),
        }
    }
}


fn good_server_node(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let salt = random_bytes(4);
    let v = G.pow_mod(&combine_salt_pw(&salt, &PASSWORD), &P);

    let (pub_key, priv_key) = gen_dh_pair(&P, &G);

    let mut check_digest = None;
    loop {
        let msg = rx.recv().unwrap();

        match msg {
            Msg::EmailPubKey { email, a_pub } => {
                if email != EMAIL {
                    tx.send(Msg::BadEmailOrPW).unwrap();
                    break;
                }

                let u = Int::from(rand::thread_rng().gen::<u128>());

                println!("b {}", priv_key);
                println!("B {}", pub_key);
                println!("u {}", u);
                println!("v {}", v);
                println!("N {}", *P);
                let check_val = (a_pub * v.pow_mod(&u, &P)).pow_mod(&priv_key, &P);
                println!("Ka {}", check_val);
                check_digest = Some(digest_ramp_int(&check_val));

                tx.send(Msg::SaltPubKey { salt: salt.clone(), b_pub: pub_key.clone(), u }).unwrap();
            },
            Msg::Check { client_check } => {
                if client_check == check_digest.unwrap() {
                    tx.send(Msg::PWAccepted).unwrap();
                } else {
                    tx.send(Msg::BadEmailOrPW).unwrap();
                }

                break;
            },
            _ => panic!("Unexpected message"),
        }
    }
}

fn evil_server_node(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let salt = random_bytes(4);
    let (pub_key, priv_key) = gen_dh_pair(&P, &G);
    let u = Int::from(rand::thread_rng().gen::<u128>());

    let mut remote_pub = None;
    loop {
        let msg = rx.recv().unwrap();

        match msg {
            Msg::EmailPubKey { email, a_pub } => {
                if email != EMAIL {
                    tx.send(Msg::BadEmailOrPW).unwrap();
                    break;
                }

                remote_pub = Some(a_pub);

                tx.send(Msg::SaltPubKey { salt: salt.clone(), b_pub: pub_key.clone(), u: u.clone() }).unwrap();
            },
            Msg::Check { client_check } => {
                tx.send(Msg::PWAccepted).unwrap();

                // this is extremely slow and would need significant optimization
                // for real world use but that's not really the point of the exercise
                for len in 0..6 {
                    println!("Trying len = {}", len);
                    for test_val in 0..26usize.pow(len as u32) {
                        let mut test_str = vec![b'a'; len];

                        let mut remainder = test_val;
                        for val in test_str.iter_mut() {
                            let offset = remainder % 26;

                            *val += offset as u8;

                            remainder /= 26;
                        }

                        let v = G.pow_mod(&combine_salt_pw(&salt, &test_str), &P);
                        let check_val = (remote_pub.as_ref().unwrap() * v.pow_mod(&u, &P)).pow_mod(&priv_key, &P);
                        if client_check == digest_ramp_int(&check_val) {
                            println!("Found password! {}", String::from_utf8_lossy(&test_str));
                            return;
                        }
                    }
                }

                println!("Failed to find password");

                return;
            },
            _ => panic!("Unexpected message"),
        }
    }
}

fn main() {
    {
        let (client_tx, server_rx) = mpsc::channel();
        let (server_tx, client_rx) = mpsc::channel();

        // A
        let client = thread::spawn(move || client_node(client_tx, client_rx));

        // B
        let server = thread::spawn(move || good_server_node(server_tx, server_rx));

        client.join().unwrap();
        server.join().unwrap();
    }

    {
        let (client_tx, server_rx) = mpsc::channel();
        let (server_tx, client_rx) = mpsc::channel();

        // A
        let client = thread::spawn(move || client_node(client_tx, client_rx));

        // B
        let server = thread::spawn(move || evil_server_node(server_tx, server_rx));

        client.join().unwrap();
        server.join().unwrap();
    }
}