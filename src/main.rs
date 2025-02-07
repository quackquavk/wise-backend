mod config;
mod handlers;
mod middleware;
mod models;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use dotenv::dotenv;
use handlers::{
    auth::{google_auth, google_auth_callback},
    protected_example::{protected_route, admin_route, get_current_user},
    ideas::{submit_idea, get_ideas, get_pending_ideas, approve_idea, vote_idea, get_idea},
};
use middleware::Authentication;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database = config::init_database()
        .await
        .expect("Failed to connect to database");

    let port = config::get_port();
    let frontend_url = std::env::var("FRONTEND_URL").expect("FRONTEND_URL must be set");

    println!("Server running at http://localhost:{}", port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&frontend_url)
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(Authentication)
            .app_data(web::Data::new(database.clone()))
            .service(
                web::scope("/api")
                    .service(google_auth)
                    .service(google_auth_callback)
                    .service(protected_route)
                    .service(admin_route)
                    .service(get_current_user)
                    .service(submit_idea)
                    .service(get_ideas)
                    .service(get_idea)
                    .service(get_pending_ideas)
                    .service(approve_idea)
                    .service(vote_idea)
            )
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
