use std::{collections::HashSet, io::Cursor};

use isahc::ReadResponseExt;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use serde::{Serialize, Deserialize};
use rocket::{get, http::{Header, Status}, launch, response::Responder, routes, Response, State};
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

#[cfg(not(debug_assertions))]
const DOMAIN: &str = "auth.insa.lol";
#[cfg(debug_assertions)]
const DOMAIN: &str = "localhost";

// https://cas.insa-rouen.fr/cas/login?service=https://insagenda.pages.insa-rouen.fr/login/global-local

enum LoginCallbackError {
    CasUnreachable,
    CasUnavailable,
    BadCasResponse,
    CasAuthenticationFailed(String),
    UserAccountDeleted,
    MissingEmail,
    MissingUid,
    MissingUidNumber,
    InvalidUidNumber,
    MissingFirstName,
    MissingFamilyName,
    CantGenerateToken(jsonwebtoken::errors::Error),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for LoginCallbackError {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let (status, body) = match self {
            LoginCallbackError::CasUnreachable => (Status::ServiceUnavailable, String::from("CAS unreachable")),
            LoginCallbackError::CasUnavailable => (Status::ServiceUnavailable, String::from("CAS unavailable")),
            LoginCallbackError::BadCasResponse => (Status::ServiceUnavailable, String::from("Bad CAS response")),
            LoginCallbackError::CasAuthenticationFailed(e) => (Status::Forbidden, format!("CAS authentication failed: {e}")),
            LoginCallbackError::UserAccountDeleted => (Status::Forbidden, String::from("Your account was deleted")),
            LoginCallbackError::MissingEmail => (Status::InternalServerError, String::from("Missing email")),
            LoginCallbackError::MissingUid => (Status::InternalServerError, String::from("Missing uid")),
            LoginCallbackError::MissingUidNumber => (Status::InternalServerError, String::from("Missing uid number")),
            LoginCallbackError::InvalidUidNumber => (Status::InternalServerError, String::from("Invalid uid number")),
            LoginCallbackError::MissingFirstName => (Status::InternalServerError, String::from("Missing first name")),
            LoginCallbackError::MissingFamilyName => (Status::InternalServerError, String::from("Missing family name")),
            LoginCallbackError::CantGenerateToken(e) => (Status::InternalServerError, format!("Can't generate token: {e}")),
        };
        Ok(Response::build()
            .status(status)
            .sized_body(body.len(), Cursor::new(body))
            .finalize())
    }
}

struct JwtToken {
    token: String,
    max_age: usize,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for JwtToken {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let token = self.token;
        let max_age = self.max_age;

        let value = format!("token={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}; Domain={DOMAIN}");
        let response = Response::build()
            .status(Status::Ok)
            .header(Header::new("Set-Cookie", value))
            .finalize();

        Ok(response)
    }
}

#[get("/login-callback?<ticket>")]
fn login_callback(key: &State<EncodingKey>, ticket: String) -> Result<JwtToken, LoginCallbackError> {
    use LoginCallbackError::*;

    // Send validate request
    let enc_ticket = urlencoding::encode(&ticket);
    let url = format!("{VALIDATE_URL}{enc_ticket}");
    let mut resp = isahc::get(url).map_err(|_| CasUnreachable)?;
    if resp.status() != 200 {
        return Err(CasUnavailable);
    }

    // Get info from xml
    let mut xml = resp.text().map_err(|_| BadCasResponse)?;
    if let Some(error_code) = get_all_between_strict(&xml, "<cas:authenticationFailure code=\"", "\">") {
        return Err(CasAuthenticationFailed(error_code.to_string()));
    }
    println!("{}", xml);

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

    let utc_now = chrono::Utc::now().timestamp() as usize;
    let max_age = 6 * 30 * 24 * 60 * 60;
    let claim = Claims {
        exp: utc_now + max_age,
        iat: utc_now,
        email,
        uid,
        uid_number,
        groups: groups.into_iter().collect(),
        given_name,
        family_name,
    };
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::new(Algorithm::ES256), &claim, key).map_err(CantGenerateToken)?;

    Ok(JwtToken { token, max_age })
}

#[launch]
fn rocket() -> _ {
    let private_key = std::fs::read("pkcs8.pem").expect("Failed to read private key");
    let encoding_key: EncodingKey = EncodingKey::from_ec_pem(&private_key).expect("Invalid private key");
    rocket::build()
        .manage(encoding_key)
        .mount("/", routes![login_callback])
}
