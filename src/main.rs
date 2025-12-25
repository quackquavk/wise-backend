mod config;
mod handlers;
mod middleware;
mod models;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use actix_governor::{Governor, GovernorConfigBuilder};
use dotenv::dotenv;
use handlers::{
    auth::{google_auth, google_auth_callback},
    protected_example::{protected_route, admin_route, get_current_user},
    ideas::{submit_idea, get_ideas, update_idea_status, vote_idea, delete_idea, get_archive, delete_from_archive, undo_archive, edit_idea},
    health::health_check, 
};
use middleware::Authentication;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let db_config = config::init_database()
        .await
        .expect("Failed to connect to databases");

    let port = config::get_port();

    // Configure rate limiting: 10 requests per minute
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(60)
        .finish()
        .unwrap();

   HttpServer::new(move || {
    let cors = Cors::default()
        .allowed_origin("https://rebuzz.ai")
        .allowed_origin("https://cvai.dev")
        .allowed_origin("http://localhost:5173")
        .allow_any_method()
        .allow_any_header()
        .expose_headers(vec!["x-service"])
        .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(Logger::new("%a %{User-Agent}i %r %s %b %{Referer}i %T").log_target("debug"))
            .wrap(Governor::new(&governor_conf))
            .wrap(Authentication)
            .app_data(web::Data::new(db_config.clone()))
            .service(
                web::scope("/api")
                    .service(google_auth)
                    .service(google_auth_callback)
                    .service(protected_route)
                    .service(admin_route)
                    .service(get_current_user)
                    .service(submit_idea)
                    .service(get_ideas)
                    .service(update_idea_status)
                    .service(vote_idea)
                    .service(delete_idea)
                    .service(get_archive)
                    .service(health_check)
                    .service(delete_from_archive)
                    .service(undo_archive)
                    .service(edit_idea)
            )
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
