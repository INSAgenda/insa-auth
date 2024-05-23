use serde::{Serialize, Deserialize};
use rocket::{get, launch, routes};

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

#[get("/world")]
fn world() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![world])
}
