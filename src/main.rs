mod config;
mod handlers;
mod middleware;
mod models;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use dotenv::dotenv;
use handlers::auth::{login, register};
use middleware::Authentication;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database = config::init_database()
        .await
        .expect("Failed to connect to database");

    let port = config::get_port();

    println!("Server running at http://localhost:{}", port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(Authentication)
            .app_data(web::Data::new(database.clone()))
            .service(
                web::scope("/api")
                    .service(register)
                    .service(login)
            )
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
