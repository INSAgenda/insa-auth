//! Services redirect to this page to initiate the login process.
//! We must redirect the user to their provided callback URL after the login process.

use super::*;

pub struct ProviderLoginResponse(String);

impl <'r, 'o: 'r> Responder<'r, 'o> for ProviderLoginResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let mut response = Response::build();
        let response = response.status(Status::SeeOther)
            .header(Header::new("Location", self.0));
        Ok(response.finalize())
    }
}

#[get("/cas/login?<service>")]
pub async fn provider_login(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>, service: String) -> ProviderLoginResponse {
    // TODO: Add a whitelist of services

    match verify(keys, cookies) {
        Ok(claims) => {
            // Generate a random small ticket
            let mut ticket = String::new();
            for _ in 0..32 {
                ticket.push((rand::random::<u8>() % 26 + 97) as char);
            }
            
            let cleaned_service = service.split_once('?').map(|(s, _)| s).unwrap_or(&service).trim_end_matches('/');
            TICKETS.write().await.insert(ticket.clone(), (now(), cleaned_service.to_owned(), claims.0));    

            let sep = if service.contains('?') { "&" } else { "?" };
            
            ProviderLoginResponse(format!("{service}{sep}ticket={ticket}"))
        },
        Err(_) => {
            let this_url = format!("/cas/login?service={}", urlencoding::encode(&service));
            let next = format!("/login?next={}", urlencoding::encode(&this_url));
            ProviderLoginResponse(next)
        },
    }
}
