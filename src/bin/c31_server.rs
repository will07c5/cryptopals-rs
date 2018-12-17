#![feature(proc_macro_hygiene, decl_macro)]

extern crate common;
#[macro_use]
extern crate rocket;
extern crate hex;

use rocket::http::Status;
use std::fs;
use std::{thread, time};
use common::sha1::{sha1_digest, HASH_SIZE};

fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    for (ab, bb) in a.iter().zip(b.iter()) {
        if *ab != *bb {
            return false;
        }

        thread::sleep(time::Duration::from_millis(50));
    }

    true
}

#[get("/test?<file>&<signature>")]
fn test_handler(file: String, signature: String) -> Status {
    let data = match fs::read(&file) {
        Ok(x) => x,
        Err(err) => {
            println!("Error opening file: {:?}", err);
            return Status::BadRequest;
        }
    };

    let sig_decode = match hex::decode(&signature) {
        Ok(x) => x,
        Err(err) => {
            println!("Error decoding hex: {:?}", err);
            return Status::BadRequest;
        }
    };

    if sig_decode.len() != HASH_SIZE {
        println!("Signature wrong length: {}", sig_decode.len());
        return Status::BadRequest;
    }

    let sig_check = sha1_digest(&data);

    if !insecure_compare(&sig_check, &sig_decode) {
        println!("{} {}", hex::encode(&sig_check), hex::encode(&sig_decode));
        Status::InternalServerError
    } else {
        Status::Ok
    }
}

fn main() {
    rocket::ignite().mount("/", routes![test_handler]).launch();
}
