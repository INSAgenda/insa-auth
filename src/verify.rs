use crate::*;

pub enum VerificationError {
    NotAuthenticated,
    InvalidToken(jsonwebtoken::errors::Error),
}

impl <'r, 'o: 'r> Responder<'r, 'o> for VerificationError {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let (status, body) = match self {
            VerificationError::NotAuthenticated => (Status::Unauthorized, String::from("Not authenticated")),
            VerificationError::InvalidToken(e) => (Status::Forbidden, format!("Invalid token: {e}")),
        };
        Ok(Response::build()
            .status(status)
            .sized_body(body.len(), Cursor::new(body))
            .finalize())
    }
}

pub struct SuccessfulVerification(Claims);

impl <'r, 'o: 'r> Responder<'r, 'o> for SuccessfulVerification {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let response = Response::build()
            .status(Status::Ok)
            .header(Header::new("X-Insa-Auth-Email", self.0.email))
            .header(Header::new("X-Insa-Auth-Uid", self.0.uid))
            .header(Header::new("X-Insa-Auth-Uid-Number", self.0.uid_number.to_string()))
            .header(Header::new("X-Insa-Auth-Groups", self.0.groups.join(",")))
            .header(Header::new("X-Insa-Auth-Given-Name", self.0.given_name))
            .header(Header::new("X-Insa-Auth-Family-Name", self.0.family_name))
            .finalize();
        Ok(response)
    }
}

#[get("/verify")]
pub fn verify(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>) -> Result<SuccessfulVerification, VerificationError> {
    let token_cookie = cookies.get("token").ok_or(VerificationError::NotAuthenticated)?;
    let token = token_cookie.value();
    let data = jsonwebtoken::decode::<Claims>(token, &keys.1, &Validation::new(Algorithm::ES256)).map_err(VerificationError::InvalidToken)?;

    Ok(SuccessfulVerification(data.claims))
}
