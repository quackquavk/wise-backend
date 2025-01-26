use actix_web::{get, web, HttpResponse};
use mongodb::Database;

use crate::middleware::auth::{require_auth, require_admin};

#[get("/protected")]
pub async fn protected_route(req: web::HttpRequest) -> HttpResponse {
    // This will return error if user is not authenticated
    let user = match require_auth(&req.into_parts().0) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    HttpResponse::Ok().json(format!("Hello, {}!", user.email))
}

#[get("/admin")]
pub async fn admin_route(req: web::HttpRequest) -> HttpResponse {
    // This will return error if user is not an admin
    let admin = match require_admin(&req.into_parts().0) {
        Ok(user) => user,
        Err(e) => return HttpResponse::Unauthorized().json(e.to_string()),
    };

    HttpResponse::Ok().json(format!("Hello admin: {}", admin.email))
} 