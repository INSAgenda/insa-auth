use crate::*;

pub enum LoginResponse {
    AlreadyLoggedIn { next: Option<String>, claims: Claims },
    Login { next: Option<String> }
}

impl <'r, 'o: 'r> Responder<'r, 'o> for LoginResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            LoginResponse::AlreadyLoggedIn { next: Some(next), .. } => {
                let mut response = Response::build();
                let response = response.status(Status::SeeOther)
                    .header(Header::new("Location", next));
                Ok(response.finalize())
            },
            LoginResponse::AlreadyLoggedIn { next: None, claims } => {
                let mut response = Response::build();
                let body = format!("{claims:?}");
                let response = response.status(Status::Ok)
                    .header(Header::new("Content-Type", "text/plain"))
                    .sized_body(body.len(), std::io::Cursor::new(body));
                Ok(response.finalize())
            }
            LoginResponse::Login { next } => {
                // let mut response = Response::build();
                // let response = response.status(Status::SeeOther)
                //     .header(Header::new("Location", LOGIN_URL));
                // if let Some(next) = next {
                //     response.header(Header::new("Set-Cookie", format!("next={next}; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=.{DOMAIN}; Max-Age=300")));
                // }
                // Ok(response.finalize())

                // TEMPORARY
                let mut response = Response::build();
                let body = include_str!("message.html");
                let response = response.status(Status::Ok)
                    .header(Header::new("Content-Type", "text/html"))
                    .sized_body(body.len(), std::io::Cursor::new(body));
                Ok(response.finalize())
            },
        }
    }
}

#[get("/login?<next>")]
pub fn login(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>, next: Option<String>) -> LoginResponse {
    match verify(keys, cookies) {
        Ok(claims) => LoginResponse::AlreadyLoggedIn { next, claims: claims.0 },
        Err(_) => LoginResponse::Login { next },
    }
}
