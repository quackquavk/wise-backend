use actix_web::{
    dev::ServiceRequest, error::ErrorUnauthorized, http::header, Error, HttpMessage,
    dev::Extensions,
};
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::config::get_jwt_secret;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // email
    pub role: String,
    pub exp: usize,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub email: String,
    pub role: String,
}

pub async fn validate_token(req: &ServiceRequest) -> Result<TokenData<Claims>, Error> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header| auth_header.to_str().ok())
        .and_then(|auth_str| {
            if auth_str.starts_with("Bearer ") {
                Some(auth_str[7..].to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| ErrorUnauthorized("No valid authorization header found"))?;

    let jwt_secret = get_jwt_secret();
    
    decode::<Claims>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| ErrorUnauthorized("Invalid token"))
}

pub fn get_current_user(extensions: &Extensions) -> Option<AuthenticatedUser> {
    extensions.get::<AuthenticatedUser>().cloned()
}

// Helper function to require authentication and get user
pub fn require_auth(extensions: &Extensions) -> Result<AuthenticatedUser, Error> {
    get_current_user(extensions).ok_or_else(|| ErrorUnauthorized("Authentication required"))
}

// Helper function to require admin role
pub fn require_admin(extensions: &Extensions) -> Result<AuthenticatedUser, Error> {
    let user = require_auth(extensions)?;
    if user.role == "Admin" {
        Ok(user)
    } else {
        Err(ErrorUnauthorized("Admin access required"))
    }
} 