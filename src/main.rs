pub use std::{collections::HashSet, io::Cursor};
pub use isahc::ReadResponseExt;
pub use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
pub use serde::{Serialize, Deserialize};
pub use rocket::{get, http::{CookieJar, Header, Status}, launch, response::Responder, routes, Response, State};
pub use string_tools::{get_all_after, get_all_between_strict};

mod validate;
pub use validate::*;
#[path ="verify.rs"]
mod verify_mod;
pub use verify_mod::*;
#[path ="login.rs"]
mod login_mod;
pub use login_mod::*;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize, // Expiration time (as UTC timestamp)
    iat: usize, // Issued at (as UTC timestamp)

    email: String, // firstname.name@insa-rouen.fr
    uid: String, // 167900
    uid_number: usize, // fname
    groups: Vec<String>, // [ad-etudiants, etudiants, etudiants-cve ...]
    given_name: String, // Firstname
    family_name: String, // Name
}

#[cfg(not(debug_assertions))]
mod constants {
    pub const VALIDATE_URL: &str = "https://cas.insa-rouen.fr/cas/p3/serviceValidate?service=https%3A%2F%2Finsagenda.pages.insa-rouen.fr%2Flogin%2Fglobal&ticket=";
    pub const DOMAIN: &str = "insa.lol";
    pub const LOGIN_URL: &str = "https://cas.insa-rouen.fr/cas/login?service=https://insagenda.pages.insa-rouen.fr/login/global";
}

#[cfg(debug_assertions)]
mod constants {
    pub const VALIDATE_URL: &str = "https://cas.insa-rouen.fr/cas/p3/serviceValidate?service=https%3A%2F%2Finsagenda.pages.insa-rouen.fr%2Flogin%2Fglobal-local&ticket=";
    pub const DOMAIN: &str = "localhost";
    pub const LOGIN_URL: &str = "https://cas.insa-rouen.fr/cas/login?service=https://insagenda.pages.insa-rouen.fr/login/global-local";
}

use constants::*;

#[launch]
fn rocket() -> _ {
    let private_key = std::fs::read("private.pem").expect("Failed to read private key");
    let public_key = std::fs::read("public.pem").expect("Failed to read public key");
    let encoding_key: EncodingKey = EncodingKey::from_ec_pem(&private_key).expect("Invalid private key");
    let decoding_key: DecodingKey = DecodingKey::from_ec_pem(&public_key).expect("Invalid public key");
    rocket::build()
        .manage((encoding_key, decoding_key))
        .mount("/", routes![login_callback, verify, login])
}
