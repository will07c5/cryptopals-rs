extern crate common;
extern crate rand;
extern crate ramp;
extern crate hex;

use ramp::Int;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use common::dh::{gen_dh_pair, P, G};
use common::sha1::sha1_digest;
use common::util::random_bytes;

enum Msg {
    EmailPubKey {
        email: Vec<u8>,
        a_pub: Int,
    },
    SaltPubKey {
        salt: Vec<u8>,
        b_pub: Int,
    },
    Check {
        client_check: Vec<u8>
    },
    BadEmailOrPW,
    PWAccepted,
}

const PASSWORD: &[u8] = b"a very secure password!";
const EMAIL: &[u8] = b"foo@example.com";
const K: usize = 3;

fn combine_pub_keys(a_pub: &Int, b_pub: &Int) -> Int {
    let mut sha_input = Vec::new();
    sha_input.extend_from_slice(&a_pub.to_str_radix(16, false).as_bytes()); 
    sha_input.extend_from_slice(&b_pub.to_str_radix(16, false).as_bytes()); 
    let u_h = sha1_digest(&sha_input);
    
    Int::from_str_radix(&hex::encode(&u_h), 16).unwrap()
}

fn combine_salt_pw(salt: &[u8], pw: &[u8]) -> Int {
    let mut sha_input = Vec::new();
    sha_input.extend_from_slice(&salt);
    sha_input.extend_from_slice(&pw);
    let x_h = sha1_digest(&sha_input);
    // there's probably a less stupid way to do this but this works for now
    Int::from_str_radix(&hex::encode(&x_h), 16).unwrap()
}

fn client_node(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let (pub_key, priv_key) = gen_dh_pair(&P, &G);

    tx.send(Msg::EmailPubKey { email: EMAIL.to_vec(), a_pub: pub_key.clone() }).unwrap();

    loop {
        let msg = rx.recv().unwrap();

        match msg {
            Msg::SaltPubKey { salt, b_pub } => {
                let u = combine_pub_keys(&pub_key, &b_pub);
                let x = combine_salt_pw(&salt, &PASSWORD);
                let k = Int::from(K);

                let check_val = (b_pub - k * G.pow_mod(&x, &P)).pow_mod(&(&priv_key + u * x), &P); 
                let check_digest = sha1_digest(&check_val.to_str_radix(16, false).as_bytes());

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


fn server_node(tx: Sender<Msg>, rx: Receiver<Msg>) {
    let salt = random_bytes(4);
    let v = G.pow_mod(&combine_salt_pw(&salt, &PASSWORD), &P);

    let (mut pub_key, priv_key) = gen_dh_pair(&P, &G);
    pub_key += Int::from(K) * &v;

    let mut check_digest = None;
    loop {
        let msg = rx.recv().unwrap();

        match msg {
            Msg::EmailPubKey { email, a_pub } => {
                if email != EMAIL {
                    tx.send(Msg::BadEmailOrPW).unwrap();
                    break;
                }

                let u = combine_pub_keys(&a_pub, &pub_key);

                let check_val = (a_pub * v.pow_mod(&u, &P)).pow_mod(&priv_key, &P);
                check_digest = Some(sha1_digest(&check_val.to_str_radix(16, false).as_bytes()));

                tx.send(Msg::SaltPubKey { salt: salt.clone(), b_pub: pub_key.clone() }).unwrap();
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

fn main() {
    let (client_tx, server_rx) = mpsc::channel();
    let (server_tx, client_rx) = mpsc::channel();

    // A
    let client = thread::spawn(move || client_node(client_tx, client_rx));

    // B
    let server = thread::spawn(move || server_node(server_tx, server_rx));

    client.join().unwrap();
    server.join().unwrap();
}