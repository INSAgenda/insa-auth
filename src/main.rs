use std::{collections::HashSet, io::Cursor};

use isahc::ReadResponseExt;
use serde::{Serialize, Deserialize};
use rocket::{get, http::Status, launch, response::Responder, routes};
use string_tools::{get_all_after, get_all_between_strict};

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
const VALIDATE_URL: &str = "https://cas.insa-rouen.fr/cas/p3/serviceValidate?service=https%3A%2F%2Finsagenda.pages.insa-rouen.fr%2Flogin%2Fglobal&ticket=";
#[cfg(debug_assertions)]
const VALIDATE_URL: &str = "https://cas.insa-rouen.fr/cas/p3/serviceValidate?service=https%3A%2F%2Finsagenda.pages.insa-rouen.fr%2Flogin%2Fglobal-local&ticket=";

// https://cas.insa-rouen.fr/cas/login?service=https://insagenda.pages.insa-rouen.fr/login/global-local

enum LoginCallbackError {
    CasUnreachable,
    CasAuthenticationFailed,
    BadCasResponse,
    UserAccountDeleted,
    MissingEmail,
    MissingUid,
    MissingUidNumber,
    InvalidUidNumber,
    MissingFirstName,
    MissingFamilyName,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for LoginCallbackError {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let (status, body) = match self {
            LoginCallbackError::CasUnreachable => (Status::ServiceUnavailable, "CAS unreachable"),
            LoginCallbackError::BadCasResponse => (Status::ServiceUnavailable, "Bad CAS response"),
            LoginCallbackError::CasAuthenticationFailed => (Status::Unauthorized, "CAS authentication failed"),
            LoginCallbackError::UserAccountDeleted => (Status::Forbidden, "Your account was deleted"),
            LoginCallbackError::MissingEmail => (Status::InternalServerError, "Missing email"),
            LoginCallbackError::MissingUid => (Status::InternalServerError, "Missing uid"),
            LoginCallbackError::MissingUidNumber => (Status::InternalServerError, "Missing uid number"),
            LoginCallbackError::InvalidUidNumber => (Status::InternalServerError, "Invalid uid number"),
            LoginCallbackError::MissingFirstName => (Status::InternalServerError, "Missing first name"),
            LoginCallbackError::MissingFamilyName => (Status::InternalServerError, "Missing family name"),
        };
        Ok(rocket::Response::build()
            .status(status)
            .sized_body(body.len(), Cursor::new(body))
            .finalize())
    }
}

#[get("/login-callback?<ticket>")]
fn login_callback(ticket: String) -> Result<&'static str, LoginCallbackError> {
    use LoginCallbackError::*;

    // Send validate request
    let enc_ticket = urlencoding::encode(&ticket);
    let url = format!("{VALIDATE_URL}{enc_ticket}");
    let mut resp = isahc::get(url).map_err(|_| CasUnreachable)?;
    if resp.status() != 200 {
        return Err(CasAuthenticationFailed);
    }

    // Get info from xml
    let mut xml = resp.text().map_err(|_| BadCasResponse)?;

    let email = get_all_between_strict(&xml, "<cas:mail>", "</cas:mail>")
        .ok_or(MissingEmail)?
        .to_string();

    let uid = get_all_between_strict(&xml, "<cas:uid>", "</cas:uid>")
        .ok_or(MissingUid)?
        .to_string();

    let uid_number = get_all_between_strict(&xml, "<cas:uidNumber>", "</cas:uidNumber>")
        .ok_or(MissingUidNumber)?
        .parse::<usize>()
        .map_err(|_| InvalidUidNumber)?;

    let given_name = get_all_between_strict(&xml, "<cas:givenName>", "</cas:givenName>")
        .ok_or(MissingFirstName)?
        .to_string();

    let family_name = get_all_between_strict(&xml, "<cas:sn>", "</cas:sn>")
        .ok_or(MissingFamilyName)?
        .to_string();

    // Check banned users
    if [
        "tom.poget@insa-rouen.fr",
        "baptiste.hersent@insa-rouen.fr",
        "michel.vespier@insa-rouen.fr",
    ]
    .contains(&email.as_str())
    {
        return Err(UserAccountDeleted);
    }

    // Get groups
    let mut groups = HashSet::new();
    while let Some(official_group) = get_all_between_strict(&xml, "<cas:supannAffectation>", "</cas:supannAffectation>") {
        groups.insert(official_group.to_string());
        xml = get_all_after(&xml, "</cas:supannAffectation>").to_string();
    }

    Ok("ok")
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![login_callback])
}
