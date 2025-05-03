//! Services redirect to this page to initiate the login process.
//! We must redirect the user to their provided callback URL after the login process.

use super::*;
use url::Url;

const WHITELIST: [&str; 1] = [
    "mastodon.insa.lol",
    "stotra.insa.lol",
];

pub enum ProviderLoginResponse {
    InvalidServiceUrl(url::ParseError),
    Unauthorized,
    Next(String)
}

impl <'r, 'o: 'r> Responder<'r, 'o> for ProviderLoginResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            ProviderLoginResponse::InvalidServiceUrl(err) => {
                let mut response = Response::build();
                let response = response.status(Status::BadRequest)
                    .header(Header::new("Content-Type", "text/plain"));
                let body = format!("Invalid service URL: {err}");
                response.sized_body(body.len(), std::io::Cursor::new(body));
                Ok(response.finalize())
            },
            ProviderLoginResponse::Unauthorized => {
                let mut response = Response::build();
                let response = response.status(Status::Unauthorized)
                    .header(Header::new("Content-Type", "text/plain"));
                let body = "Unauthorized";
                response.sized_body(body.len(), std::io::Cursor::new(body));
                Ok(response.finalize())
            },
            ProviderLoginResponse::Next(next) => {
                let mut response = Response::build();
                let response = response.status(Status::SeeOther)
                    .header(Header::new("Location", next));
                Ok(response.finalize())
            },
        }
    }
}

#[get("/cas/login?<service>")]
pub async fn provider_login(keys: &State<(EncodingKey, DecodingKey)>, cookies: &CookieJar<'_>, service: String) -> ProviderLoginResponse {
    // Verify service URL
    let url = match Url::parse(&service) {
        Ok(url) => url,
        Err(e) => return ProviderLoginResponse::InvalidServiceUrl(e),
    };
    let host_str = match url.host_str() {
        Some(host) => host,
        None => return ProviderLoginResponse::InvalidServiceUrl(url::ParseError::EmptyHost),
    };
    if !WHITELIST.contains(&host_str) {
        return ProviderLoginResponse::Unauthorized;
    }

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
            
            ProviderLoginResponse::Next(format!("{service}{sep}ticket={ticket}"))
        },
        Err(_) => {
            let this_url = format!("/cas/login?service={}", urlencoding::encode(&service));
            let next = format!("/login?next={}", urlencoding::encode(&this_url));
            ProviderLoginResponse::Next(next)
        },
    }
}
