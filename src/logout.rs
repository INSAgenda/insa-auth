use crate::*;

pub struct LogoutResponse {
    claims: Option<Claims>
}

impl <'r, 'o: 'r> Responder<'r, 'o> for LogoutResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let body = match self.claims {
            Some(claims) => format!("Successfully logged out.\n\n{claims:?}"),
            None => String::from("You were not logged in."),
        };

        let remove_cookie = format!("token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Domain=.{DOMAIN}");

        let mut response = Response::build();
        let response = response.status(Status::Ok)
            .header(Header::new("Content-Type", "text/plain"))
            .header(Header::new("Set-Cookie", remove_cookie))
            .sized_body(body.len(), std::io::Cursor::new(body));
        Ok(response.finalize())
    }
}

#[get("/logout")]
pub fn logout(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>) -> LogoutResponse {
    match verify(keys, cookies) {
        Ok(claims) => LogoutResponse { claims: Some(claims.0) },
        Err(_) => LogoutResponse { claims: None },
    }
}
