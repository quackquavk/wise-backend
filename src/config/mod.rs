use mongodb::{Client, Database};
use std::env;

pub async fn init_database() -> mongodb::error::Result<Database> {
    let mongodb_uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let database_name = env::var("DATABASE_NAME").expect("DATABASE_NAME must be set");
    
    log::info!("Connecting to MongoDB database: {}", database_name);
    
    let client = Client::with_uri_str(&mongodb_uri).await?;
    
    // Test the connection
    match client.list_database_names(None, None).await {
        Ok(names) => {
            log::info!("Successfully connected to MongoDB. Available databases: {:?}", names);
        }
        Err(e) => {
            log::error!("Failed to list databases: {}", e);
        }
    }
    
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