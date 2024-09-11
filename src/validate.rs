use crate::*;

pub enum LoginCallbackError {
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

pub struct JwtToken {
    token: String,
    max_age: usize,
    next: Option<String>,
}

impl<'r, 'o: 'r> Responder<'r, 'o> for JwtToken {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let token = self.token;
        let max_age = self.max_age;

        let value = format!("token={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}; Domain=.{DOMAIN}");
        let mut response = Response::build();
        let response = response.status(Status::Ok)
            .header(Header::new("Set-Cookie", value));
        
        // This could be a nice open-redirect vulnerability here but it actually can't be exploited
        let next = self.next.unwrap_or_else(|| "/login".to_string());
        response.status(Status::SeeOther);
        response.header(Header::new("Location", next));
        
        Ok(response.finalize())
    }
}

#[get("/login-callback?<ticket>")]
pub fn login_callback(keys: &State<(EncodingKey, DecodingKey)>, ticket: String, cookies: &CookieJar<'_>) -> Result<JwtToken, LoginCallbackError> {
    use LoginCallbackError::*;

    // Send validate request
    let enc_ticket = urlencoding::encode(&ticket);
    let url = format!("{VALIDATE_URL}{enc_ticket}");
    let mut resp = isahc::get(url).map_err(|_| CasUnreachable)?; // TODO: async
    if resp.status() != 200 {
        return Err(CasUnavailable);
    }

    // Get info from xml
    let mut xml = resp.text().map_err(|_| BadCasResponse)?;
    if let Some(error_code) = get_all_between_strict(&xml, "<cas:authenticationFailure code=\"", "\">") {
        return Err(CasAuthenticationFailed(error_code.to_string()));
    }

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

    let mut groups = HashSet::new();
    while let Some(official_group) = get_all_between_strict(&xml, "<cas:supannAffectation>", "</cas:supannAffectation>") {
        groups.insert(official_group.to_string());
        xml = get_all_after(&xml, "</cas:supannAffectation>").to_string();
    }

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

    // Generate token
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
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::new(Algorithm::ES256), &claim, &keys.0).map_err(CantGenerateToken)?;

    Ok(JwtToken {
        token,
        max_age,
        next: cookies.get("next").map(|c| c.value().to_string()),
    })
}
