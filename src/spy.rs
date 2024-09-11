use crate::*;
use std::net::IpAddr;

pub struct SpyResponse {
    next: Option<String>
}

impl <'r, 'o: 'r> Responder<'r, 'o> for SpyResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let next = self.next.unwrap_or_else(|| String::from("https://www.youtube.com/watch?v=dQw4w9WgXcQ"));
        let mut response = Response::build();
        let response = response.status(Status::SeeOther)
            .header(Header::new("Location", next));
        Ok(response.finalize())
    }
}

#[get("/s?<next>")]
pub fn spy(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>, next: Option<String>, ip: IpAddr) -> SpyResponse {
    let claims = verify(keys, cookies);

    match claims {
        Ok(claims) => println!("{}: {:?}", ip, claims.0),
        Err(_) => println!("{}: Not logged in", ip),
    }

    SpyResponse { next }
}
