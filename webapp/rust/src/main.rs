#[macro_use]
extern crate actix_web;
extern crate rand;
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

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlPool, MySqlQueryAs};
use tera::Tera;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::seq::SliceRandom;

struct Context {
    db_pool: MySqlPool,
    templates: tera::Tera,
}
fn render(templates: &tera::Tera, ctx: Option<tera::Context>, name: &str) -> Result<HttpResponse> {
    let ctx = ctx.map_or(tera::Context::new(), |v| v);
    let view = templates
        .render(name, &ctx)
        .map_err(|e| error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(view))
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct User {
    id: u64,
    name: String,
    salt: String,
    password: String,
    display_name: String,
    avatar_icon: String,
    created_at: NaiveDateTime,
}

async fn get_user(pool: &MySqlPool, user_id: i64) -> anyhow::Result<User> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    return Ok(user);
}

async fn add_message(
    channel_id: i64,
    user_id: i64,
    content: &str,
    pool: &MySqlPool,
) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())",
    )
    .bind(channel_id)
    .bind(user_id)
    .bind(content)
    .execute(&mut tx)
    .await?;
    let rec: (u64,) = sqlx::query_as("SELECT LAST_INSERT_ID()")
        .fetch_one(&mut tx)
        .await?;
    tx.commit().await?;
    return Ok(rec.0);
}

async fn query_messages(
    pool: &MySqlPool,
    chan_id: i64,
    last_id: i64,
) -> anyhow::Result<Vec<Message>> {
    let msgs = sqlx::query_as::<_, Message>(
        "SELECT * FROM message WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100",
    )
    .bind(last_id)
    .bind(chan_id)
    .fetch_all(pool)
    .await?;
    return Ok(msgs);
}

fn sess_user_id(session: &Session) -> Option<i64> {
    session.get::<i64>("user_id").map_or(None, |v| v)
}

fn sess_set_user_id(session: &Session, id: i64) -> Result<()> {
    session.set("user_id", id)?;
    Ok(())
}

async fn ensure_login(data: &web::Data<Context>, session: Session) -> Option<User> {
    let pool = &data.db_pool;
    let uid = sess_user_id(&session);
    if let Some(id) = uid {
        if let Ok(user) = get_user(pool, id).await {
            return Some(user);
        }
        session.remove("user_id");
    }
    return None;
}

const LETTERS_AND_DIGITS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn random_string(size: usize) -> String {
    let mut rng = &mut rand::thread_rng();

    String::from_utf8(
        LETTERS_AND_DIGITS
            .as_bytes()
            .choose_multiple(&mut rng, size)
            .cloned()
            .collect(),
    )
    .unwrap()
}

async fn register(pool: &MySqlPool, name: &str, password: &str) -> anyhow::Result<u64> {
    let salt = random_string(20 as usize);
    let mut hasher = Sha1::new();
    hasher.input_str(&(salt.clone() + &password));
    let hex = hasher.result_str();

    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        &("INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at)"
            .to_owned()
            + "VALUES (?, ?, ?, ?, ?, NOW())"),
    )
    .bind(&name)
    .bind(salt)
    .bind(hex)
    .bind(&name)
    .bind("default.png")
    .execute(&mut tx)
    .await?;
    let ret: (u64,) = sqlx::query_as("SELECT LAST_INSERT_ID()")
        .fetch_one(&mut tx)
        .await?;
    let last_id = ret.0;
    tx.commit().await?;
    Ok(last_id)
}

// request handlers

#[get("initialize")]
async fn get_initialize(data: web::Data<Context>) -> Result<HttpResponse> {
    let pool = &data.db_pool;
    sqlx::query("DELETE FROM user WHERE id > 1000")
        .execute(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sqlx::query("DELETE FROM image WHERE id > 1001")
        .execute(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sqlx::query("DELETE FROM channel WHERE id > 10")
        .execute(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sqlx::query("DELETE FROM message WHERE id > 10000")
        .execute(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sqlx::query("DELETE FROM haveread")
        .execute(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::new(StatusCode::NO_CONTENT))
}

#[get("/")]
async fn get_index(data: web::Data<Context>, session: Session) -> Result<HttpResponse> {
    let templates = &data.templates;

    if let Some(_) = session.get::<i32>("user_id")? {
        return Ok(redirect_to(&"/channel/1").await);
    }

    render(templates, None, "index.html")
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct ChannelInfo {
    id: i64,
    name: String,
    description: String,
    updated_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

// /channel/:channel_id
async fn get_channel(
    session: Session,
    data: web::Data<Context>,
    path: web::Path<(i64,)>,
) -> Result<HttpResponse> {
    let user = ensure_login(&data, session).await;
    if user.is_none() {
        return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
    }
    let channel_id = path.0;
    let pool = &data.db_pool;

    let channels = sqlx::query_as::<_, ChannelInfo>("SELECT * FROM channel ORDER BY id")
        .fetch_all(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    let desc = &channels
        .iter()
        .find(|x| x.id == channel_id)
        .unwrap()
        .description;

    let mut ctx = tera::Context::new();
    ctx.insert("channel_id", &0);
    ctx.insert("channels", &channels);
    ctx.insert("user", &user);
    ctx.insert("description", &desc);

    render(&data.templates, Some(ctx), "channel.html")
}

#[get("register")]
async fn get_register(data: web::Data<Context>) -> Result<HttpResponse> {
    let channels: Vec<ChannelInfo> = Vec::new();
    let mut ctx = tera::Context::new();
    ctx.insert("channel_id", &0);
    ctx.insert("channels", &channels);

    render(&data.templates, Some(ctx), "register.html")
}

#[derive(Deserialize)]
struct FormUser {
    name: String,
    password: String,
}

#[post("register")]
async fn post_register(
    session: Session,
    data: web::Data<Context>,
    form: web::Form<FormUser>,
) -> Result<HttpResponse> {
    let name = &form.name;
    let pw = &form.password;
    if name == "" || pw == "" {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }
    let pool = &data.db_pool;
    // TODO Duplicated Id Errorの実装
    let user_id = register(pool, &name, &pw)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sess_set_user_id(&session, user_id as i64)?;
    Ok(redirect_to(&"/").await)
}

#[get("login")]
async fn get_login(data: web::Data<Context>) -> Result<HttpResponse> {
    let templates = &data.templates;
    let view = templates
        .render("login.html", &tera::Context::new())
        .map_err(|e| error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(view))
}

#[post("login")]
async fn post_login(
    session: Session,
    data: web::Data<Context>,
    form: web::Form<FormUser>,
) -> Result<HttpResponse> {
    let name = &form.name;
    let pw = &form.password;
    if name == "" || pw == "" {
        return Ok(HttpResponse::new(StatusCode::BAD_REQUEST));
    }
    let pool = &data.db_pool;
    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    let mut hasher = Sha1::new();
    hasher.input_str(&(user.salt.clone() + pw));
    let hex = hasher.result_str();
    if hex != user.password {
        return Ok(HttpResponse::new(StatusCode::FORBIDDEN));
    }
    sess_set_user_id(&session, user.id as i64)?;
    Ok(redirect_to(&"/").await)
}

#[get("add_channel")]
async fn get_add_channel(data: web::Data<Context>, session: Session) -> Result<HttpResponse> {
    let pool = &data.db_pool;

    let user = ensure_login(&data, session).await;
    if user.is_none() {
        return Ok(redirect_to("/").await);
    }

    let channels = sqlx::query_as::<_, ChannelInfo>("SELECT * FROM channel ORDER BY id")
        .fetch_all(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    let mut ctx = tera::Context::new();
    ctx.insert("channel_id", &0);
    ctx.insert("channels", &channels);
    ctx.insert("user", &user);

    render(&data.templates, Some(ctx), "add_channel.html")
}

#[derive(Deserialize)]
struct FormChannel {
    name: String,
    description: String,
}

#[post("add_channel")]
async fn post_add_channel(
    data: web::Data<Context>,
    session: Session,
    form: web::Form<FormChannel>,
) -> Result<HttpResponse> {
    let pool = &data.db_pool;

    let user = ensure_login(&data, session).await;
    if user.is_none() {
        return Ok(redirect_to("/").await);
    }

    let name = &form.name;
    let desc = &form.description;

    if name.is_empty() || desc.is_empty() {
        return Ok(HttpResponse::BadRequest().finish());
    }

    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO channel (name, description, updated_at, created_at) VALUES (?, ?, NOW(), NOW())"
    )
    .bind(name)
    .bind(desc)
    .execute(&mut tx)
    .await.map_err(|e| error::ErrorInternalServerError(e))?;
    let ret: (u64,) = sqlx::query_as("SELECT LAST_INSERT_ID()")
        .fetch_one(&mut tx)
        .await
        .unwrap();
    let last_id = ret.0;
    tx.commit().await.unwrap();
    Ok(redirect_to(&format!("/channel/{}", last_id)).await)
}

#[derive(Deserialize)]
struct QueryMessage {
    channel_id: i64,
    last_id: i64,
}

#[derive(Serialize, Deserialize)]
struct ServiceMessage {
    id: i64,
    user: User,
    date: String,
    content: String,
}

async fn jsonify_message(pool: &MySqlPool, m: &Message) -> ServiceMessage {
    let user =
        sqlx::query_as::<_, User>("SELECT name, display_name, avatar_icon FROM user WHERE id = ?")
            .bind(m.user_id)
            .fetch_one(pool)
            .await
            .expect("can't get user for service message");
    ServiceMessage {
        id: m.id,
        user: user,
        date: m.created_at.format("%Y/%m/%d %T").to_string(),
        content: m.content.to_string(),
    }
}

#[get("message")]
async fn get_message(
    session: Session,
    data: web::Data<Context>,
    query: web::Query<QueryMessage>,
) -> Result<HttpResponse> {
    let user_id = sess_user_id(&session);
    if user_id.is_none() {
        return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
    }

    let pool = &data.db_pool;
    let channel_id = query.channel_id;
    let last_id = query.last_id;

    let messages = query_messages(pool, channel_id, last_id)
        .await
        .expect("can't get messages");

    let num_messages = messages.len();
    let mut response: Vec<ServiceMessage> = Vec::new();
    for i in 0..num_messages {
        let message = &messages[i];
        let smessage = jsonify_message(pool, message).await;
        response.push(smessage);
    }

    if num_messages > 0 {
        let last_inserted_id = messages[0].id;
        sqlx::query(
            &("INSERT INTO haveread (user_id, channel_id, message_id, updated_at, created_at)"
                .to_owned()
                + " VALUES (?, ?, ?, NOW(), NOW())"
                + "ON DUPLICATE KEY UPDATE message_id = ?, updated_at = NOW()"),
        )
        .bind(user_id)
        .bind(channel_id)
        .bind(last_inserted_id)
        .bind(last_inserted_id)
        .execute(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    }
    let json = serde_json::to_string(&response).expect("can not convert to json from messages");
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(json))
}

#[post("message")]
async fn post_message(data: web::Data<Context>) -> Result<HttpResponse> {
    // TODO モックデータを置き換える
    add_message(200, 200, "カキクケコ", &data.db_pool)
        .await
        .unwrap();
    Ok(HttpResponse::new(StatusCode::NO_CONTENT))
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct Message {
    id: i64,
    channel_id: i64,
    user_id: i64,
    content: String,
    created_at: NaiveDateTime,
}

async fn not_found() -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/404.html")?.set_status_code(StatusCode::NOT_FOUND))
}

async fn redirect_to(path: &str) -> HttpResponse {
    HttpResponse::build(StatusCode::SEE_OTHER)
        .header(header::LOCATION, path)
        .finish()
}

/// response body
async fn response_body(path: web::Path<String>) -> HttpResponse {
    let text = format!("Hello {}!", *path);

    let (tx, rx_body) = mpsc::channel();
    let _ = tx.send(Ok::<_, Error>(Bytes::from(text)));

    HttpResponse::Ok().streaming(rx_body)
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    env_logger::init();

    // database connection
    let database_url =
        "mysql://isucon:isucon@192.168.33.10:3306/isubata?parseTime=true&loc=Local&charset=utf8mb4";
    let pool = MySqlPool::builder()
        .max_size(5) // maximum number of connections in the pool
        .build(&database_url)
        .await
        .unwrap();

    HttpServer::new(move || {
        // static ディレクトリを指定して, Teraを初期化
        let templates = Tera::new("views/*").unwrap();

        App::new()
            // setup DB pool to be used with web::Data<Pool> extractor
            .data(Context {
                db_pool: pool.clone(),
                templates: templates.clone(),
            })
            // cookie session middleware
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            // enable logger - always register actix-web Logger middleware last
            .wrap(middleware::Logger::default())
            .service(get_initialize)
            .service(get_index)
            .service(get_register)
            .service(post_register)
            .service(get_login)
            .service(post_login)
            .service(web::resource("/channel/{channel_id}").route(web::get().to(get_channel)))
            .service(get_message)
            .service(post_message)
            .service(get_add_channel)
            .service(post_add_channel)
            // async response body
            .service(web::resource("/async-body/{name}").route(web::get().to(response_body)))
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
            .service(fs::Files::new("", "../public").show_files_listing())
            // default
            .default_service(
                // 404 for GET request
                web::resource("")
                    .route(web::get().to(not_found))
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
