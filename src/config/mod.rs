use mongodb::{Client, Database};
use std::env;

pub async fn init_database() -> mongodb::error::Result<Database> {
    let mongodb_uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let database_name = env::var("DATABASE_NAME").expect("DATABASE_NAME must be set");
    
    let client = Client::with_uri_str(&mongodb_uri).await?;
    Ok(client.database(&database_name))
}

pub fn get_jwt_secret() -> String {
    env::var("JWT_SECRET").expect("JWT_SECRET must be set")
}

pub fn get_port() -> u16 {
    env::var("PORT")
        .expect("PORT must be set")
        .parse()
        .expect("PORT must be a number")
} 