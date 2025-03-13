use mongodb::{Client, Database};
use std::env;

#[derive(Clone)]
pub struct DatabaseConfig {
    pub wise_db: Database,
    pub cvai_db: Database,
}

impl DatabaseConfig {
    pub fn get_database_for_service(&self, service: &str) -> &Database {
        match service {
            "cvai" => &self.cvai_db,
            _ => &self.wise_db,  // Default to wise database
        }
    }
}

pub async fn init_database() -> mongodb::error::Result<DatabaseConfig> {
    let mongodb_uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let wise_db_name = env::var("DATABASE_NAME_WISE_SUGGESTIONS").expect("DATABASE_NAME_WISE_SUGGESTIONS must be set");
    let cvai_db_name = env::var("DATABASE_NAME_CVAI").expect("DATABASE_NAME_CVAI must be set");
    
    log::info!("Connecting to MongoDB databases: {} and {}", wise_db_name, cvai_db_name);
    
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
    
    Ok(DatabaseConfig {
        wise_db: client.database(&wise_db_name),
        cvai_db: client.database(&cvai_db_name),
    })
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