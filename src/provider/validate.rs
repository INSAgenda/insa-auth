//! This endpoint is called by services to request claims from a short-lived ticket.

use super::*;

pub enum ProviderValidateResponse {
    Ok(Claims),
    TicketDoesNotExist,
    ServiceMismatch { expected: String, got: String },
}

impl <'r, 'o: 'r> Responder<'r, 'o> for ProviderValidateResponse {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        match self {
            ProviderValidateResponse::Ok(claims) => {
                let username = claims.email.split_once('@').map(|(username, _)| username).unwrap_or(&claims.email).replace('.', "_");
                let email = &claims.email;
                let uid = &claims.uid;
                let uid_number = &claims.uid_number;
                let given_name = &claims.given_name;
                let family_name = &claims.family_name;
                let picture = format!("https://api.dicebear.com/5.x/identicon/png?seed={uid}");

                let mut response = Response::build();
                let response = response.status(Status::Ok)
                    .header(Header::new("Content-Type", "text/xml"));
                let body = format!(
                    r#"
                    <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                        <cas:authenticationSuccess>
                            <cas:user>{username}</cas:user>
                            <cas:attributes>
                                <cas:uid>{uid}</cas:uid>
                                <cas:uidNumber>{uid_number}</cas:uidNumber>
                                <cas:givenName>{given_name}</cas:givenName>
                                <cas:sn>{family_name}</cas:sn>
                                <cas:mail>{email}</cas:mail>
                                <cas:picture>{picture}</cas:picture>
                            </cas:attributes>
                        </cas:authenticationSuccess>
                    </cas:serviceResponse>
                "#);
                response.sized_body(body.len(), Cursor::new(body));
                Ok(response.finalize())
            },
            ProviderValidateResponse::TicketDoesNotExist => {
                let mut response = Response::build();
                let response = response.status(Status::BadRequest)
                    .header(Header::new("Content-Type", "text/xml"));
                let body = r#"
                    <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                        <cas:authenticationFailure code="INVALID_TICKET">
                            Ticket does not exist. Might have expired (5 minutes) or been used already.
                        </cas:authenticationFailure>
                    </cas:serviceResponse>
                "#;
                response.sized_body(body.len(), Cursor::new(body));
                Ok(response.finalize())
            },
            ProviderValidateResponse::ServiceMismatch { expected, got } => {
                let mut response = Response::build();
                let response = response.status(Status::BadRequest)
                    .header(Header::new("Content-Type", "text/xml"));
                let body = format!(r#"
                    <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                        <cas:authenticationFailure code="INVALID_SERVICE">
                            Service mismatch: expected {expected}, got {got}.
                        </cas:authenticationFailure>
                    </cas:serviceResponse>
                "#);
                response.sized_body(body.len(), Cursor::new(body));
                Ok(response.finalize())
            },
        }
    }
}

#[get("/cas/serviceValidate?<ticket>&<service>")]
pub async fn provider_validate(ticket: String, service: String) -> ProviderValidateResponse {
    let mut tickets = TICKETS.write().await;
    let now = now();
    tickets.retain(|_, (time, _, _)| now - *time < 120);

    match tickets.remove(&ticket) {
        Some((_, expected, claims)) => {
            if expected != service {
                return ProviderValidateResponse::ServiceMismatch { expected, got: service };
            }
            ProviderValidateResponse::Ok(claims)
        },
        None => ProviderValidateResponse::TicketDoesNotExist,
    }
}
