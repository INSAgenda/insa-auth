use crate::*;

pub struct LoginResponse {
    next: Option<String>,
}

impl <'r, 'o: 'r> Responder<'r, 'o> for LoginResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let mut response = Response::build();
        let response = response.status(Status::SeeOther)
            .header(Header::new("Location", LOGIN_URL));
        if let Some(next) = self.next {
            response.header(Header::new("Set-Cookie", format!("next={next}; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=.{DOMAIN}; Max-Age=300")));
        }
        Ok(response.finalize())
    }
}

#[get("/login?<next>")]
pub fn login(next: Option<String>) -> LoginResponse {
    LoginResponse { next }
}
