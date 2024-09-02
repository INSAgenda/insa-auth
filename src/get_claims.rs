use crate::*;

pub struct GetClaimsResponse {
    claims: Claims
}

impl <'r, 'o: 'r> Responder<'r, 'o> for GetClaimsResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let mut response = Response::build();
        let response = response.status(Status::Ok);
        let claims = serde_json::to_string(&self.claims).unwrap_or_default();
        let response = response.sized_body(claims.len(), Cursor::new(claims));
        Ok(response.finalize())
    }
}

#[get("/api/claims")]
pub fn get_claims(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>) -> Result<GetClaimsResponse, VerificationError> {
    verify(keys, cookies).map(|claims| GetClaimsResponse { claims: claims.0 })
}
