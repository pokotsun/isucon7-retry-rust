#[macro_use]
extern crate actix_web;
extern crate sqlx;
extern crate tera;

use std::{env, io};

use actix_files as fs;
use actix_session::{CookieSession, Session};
use actix_utils::mpsc;
use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, guard, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer, Result,
};
use bytes::Bytes;

use sqlx::mysql::MySqlPool;
use tera::Tera;

struct Context {
    db_pool: MySqlPool,
    templates: tera::Tera,
}

/// favicon handler
#[get("/favicon")]
async fn favicon() -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/favicon.ico")?)
}

/// simple index handler
#[get("/welcome")]
async fn welcome(session: Session, req: HttpRequest) -> Result<HttpResponse> {
    println!("{:?}", req);

    // session
    let mut counter = 1;
    if let Some(count) = session.get::<i32>("counter")? {
        println!("SESSION value: {}", count);
        counter = count + 1;
    }

    // set counter to session
    session.set("counter", counter)?;

    // response
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/welcome.html")))
}

#[get("initialize")]
async fn get_initialize(data: web::Data<Context>) -> Result<HttpResponse> {
    let pool = &data.db_pool;
    sqlx::query("DELETE FROM user WHERE id > 1000").execute(pool).await.unwrap();
    sqlx::query("DELETE FROM image WHERE id > 1001").execute(pool).await.unwrap();
    sqlx::query("DELETE FROM channel WHERE id > 10").execute(pool).await.unwrap();
    sqlx::query("DELETE FROM message WHERE id > 10000").execute(pool).await.unwrap();
    sqlx::query("DELETE FROM haveread").execute(pool).await.unwrap();
    
    Ok(HttpResponse::new(StatusCode::NO_CONTENT))
}

#[get("index")]
async fn get_index(data: web::Data<Context>, session: Session) -> Result<HttpResponse> {
    // let templates = Tera::new("static/*").unwrap();
    let templates = &data.templates;

    if let Some(_) = session.get::<i32>("user_id")? {
        return Ok(HttpResponse::build(StatusCode::SEE_OTHER)
                    .header("Location", "/channel/1")
                    .finish()
                 );
    }
    let mut ctx = tera::Context::new();
    ctx.insert("channel_id", &-1);
    let view = templates.render("index.html.tera", &ctx)
        .map_err(|e| error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(view)
      )
}

/// 404 handler
async fn p404() -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/404.html")?.set_status_code(StatusCode::NOT_FOUND))
}

/// response body
async fn response_body(path: web::Path<String>) -> HttpResponse {
    let text = format!("Hello {}!", *path);

    let (tx, rx_body) = mpsc::channel();
    let _ = tx.send(Ok::<_, Error>(Bytes::from(text)));

    HttpResponse::Ok().streaming(rx_body)
}

/// handler with path parameters like `/user/{name}/`
async fn with_param(req: HttpRequest, path: web::Path<(String,)>) -> HttpResponse {
    println!("{:?}", req);

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(format!("Hello {}!", path.0))
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    env_logger::init();

    // database connection
    let database_url = "mysql://isucon:isucon@127.0.0.1:3306/isubata?parseTime=true&loc=Local&charset=utf8mb4";
    let pool = MySqlPool::builder()
        .max_size(5) // maximum number of connections in the pool
        .build(&database_url).await.unwrap();

    HttpServer::new(move || {
        // static ディレクトリを指定して, Teraを初期化
        let templates = Tera::new("template/*").unwrap();

        App::new()
            // setup DB pool to be used with web::Data<Pool> extractor
            .data(Context {  db_pool: pool.clone(), templates: templates.clone(), })
            // cookie session middleware
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            // enable logger - always register actix-web Logger middleware last
            .wrap(middleware::Logger::default())
            // register favicon
            .service(favicon)
            .service(get_initialize)
            .service(get_index)
            // register simple route, handle all methods
            .service(welcome)
            // with path parameters
            .service(web::resource("/user/{name}").route(web::get().to(with_param)))
            // async response body
            .service(
                web::resource("/async-body/{name}").route(web::get().to(response_body)),
            )
            .service(
                web::resource("/test").to(|req: HttpRequest| match *req.method() {
                    Method::GET => HttpResponse::Ok(),
                    Method::POST => HttpResponse::MethodNotAllowed(),
                    _ => HttpResponse::NotFound(),
                }),
            )
            .service(web::resource("/error").to(|| async {
                error::InternalError::new(
                    io::Error::new(io::ErrorKind::Other, "test"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }))
            // static files
            // .service(fs::Files::new("/static", "static").show_files_listing())
            // redirect
            .service(web::resource("/").route(web::get().to(|req: HttpRequest| {
                println!("{:?}", req);
                HttpResponse::Found()
                    .header(header::LOCATION, "static/welcome.html")
                    .finish()
            })))
            // default
            .default_service(
                // 404 for GET request
                web::resource("")
                    .route(web::get().to(p404))
                    // all requests that are not `GET`
                    .route(
                        web::route()
                            .guard(guard::Not(guard::Get()))
                            .to(HttpResponse::MethodNotAllowed),
                    ),
            )
    })
    .bind("127.0.0.1:5000")?
    .run()
    .await
}
