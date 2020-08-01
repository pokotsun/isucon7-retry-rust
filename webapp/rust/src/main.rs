#[macro_use]
extern crate actix_web;
extern crate rand;
extern crate sqlx;
extern crate tera;

use std::{env, ffi, io, path, thread, time};

use actix_files as fs;
use actix_multipart::Multipart;
use actix_session::{CookieSession, Session};
use actix_web::http::{header, StatusCode};
use actix_web::{error, middleware, web, App, HttpResponse, HttpServer, Result};
use futures::{StreamExt, TryStreamExt};

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlPool, MySqlQueryAs};
use tera::Tera;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::seq::SliceRandom;

const AVATAR_MAX_BYTES: usize = 1 * 1024 * 1024;

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
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sqlx::query("DELETE FROM user WHERE id > 1000")
        .execute(&mut tx)
        .await
        .and(
            sqlx::query("DELETE FROM image WHERE id > 1001")
                .execute(&mut tx)
                .await,
        )
        .and(
            sqlx::query("DELETE FROM channel WHERE id > 10")
                .execute(&mut tx)
                .await,
        )
        .and(
            sqlx::query("DELETE FROM message WHERE id > 10000")
                .execute(&mut tx)
                .await,
        )
        .and(sqlx::query("DELETE FROM haveread").execute(&mut tx).await)
        .map_err(|e| error::ErrorInternalServerError(e))?;
    tx.commit()
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::new(StatusCode::NO_CONTENT))
}

#[get("/")]
async fn get_index(data: web::Data<Context>, session: Session) -> Result<HttpResponse> {
    let templates = &data.templates;

    if let Some(_) = session.get::<i32>("user_id")? {
        return Ok(redirect_to("/channel/1"));
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
    let user = ensure_login(&data, session)
        .await
        .ok_or(error::ErrorForbidden("user not found."))?;
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
        return Err(error::ErrorBadRequest("register form is empty."));
    }
    let pool = &data.db_pool;
    let user_id = register(pool, &name, &pw)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;
    sess_set_user_id(&session, user_id as i64)?;
    Ok(redirect_to("/"))
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
        return Err(error::ErrorBadRequest("login form is empty."));
    }
    let pool = &data.db_pool;
    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .map_err(|e| error::ErrorForbidden(e))?;

    let mut hasher = Sha1::new();
    hasher.input_str(&(user.salt.clone() + pw));
    let hex = hasher.result_str();
    if hex != user.password {
        return Err(error::ErrorForbidden("login password is wrong"));
    }
    sess_set_user_id(&session, user.id as i64)?;
    Ok(redirect_to("/"))
}

#[get("logout")]
async fn get_logout(session: Session) -> Result<HttpResponse> {
    session.remove("user_id");
    Ok(redirect_to("/"))
}

#[derive(Deserialize)]
struct FormMessage {
    message: String,
    channel_id: i64,
}

#[post("message")]
async fn post_message(
    session: Session,
    data: web::Data<Context>,
    form: web::Form<FormMessage>,
) -> Result<HttpResponse> {
    let user = ensure_login(&data, session)
        .await
        .ok_or(error::ErrorBadRequest("message form is empty."))?;

    let message = &form.message;
    if message == "" {
        return Err(error::ErrorBadRequest("message is empty."));
    }

    let channel_id = form.channel_id;

    add_message(channel_id, user.id as i64, message, &data.db_pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::new(StatusCode::NO_CONTENT))
}

async fn jsonify_message(pool: &MySqlPool, m: &Message) -> ServiceMessage {
    let user = sqlx::query_as::<_, User>("SELECT * FROM user WHERE id = ?")
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
    let user_id = sess_user_id(&session).ok_or(HttpResponse::new(StatusCode::NO_CONTENT))?;

    let pool = &data.db_pool;
    let channel_id = query.channel_id;
    let last_id = query.last_message_id;

    let messages = query_messages(pool, channel_id, last_id)
        .await
        .expect("can't get messages");

    let num_messages = messages.len();
    let mut response: Vec<ServiceMessage> = Vec::new();
    for i in (0..num_messages).rev() {
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
    Ok(HttpResponse::Ok().json(response))
}

async fn query_channels(pool: &MySqlPool) -> anyhow::Result<Vec<i64>> {
    let res: Vec<i64> = sqlx::query_as::<_, (i64,)>("SELECT id FROM channel")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|x| x.0)
        .collect();
    Ok(res)
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct HaveRead {
    user_id: i64,
    channel_id: i64,
    message_id: i64,
    updated_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

async fn query_have_read(pool: &MySqlPool, user_id: i64, channel_id: i64) -> Result<i64> {
    let haveread = sqlx::query_as::<_, HaveRead>(
        "SELECT * FROM haveread WHERE user_id = ? AND channel_id = ?",
    )
    .bind(user_id)
    .bind(channel_id)
    .fetch_one(pool)
    .await;

    let message_id = match haveread {
        Ok(x) => Ok(x.message_id),
        Err(e) => match e {
            sqlx::Error::RowNotFound => Ok(0),
            err => Err(error::ErrorInternalServerError(err)),
        },
    }?;
    Ok(message_id)
}

#[derive(Serialize)]
struct UnreadNum {
    channel_id: i64,
    unread: i64,
}

#[get("fetch")]
async fn fetch_unread(session: Session, data: web::Data<Context>) -> Result<HttpResponse> {
    let user_id = sess_user_id(&session).ok_or(error::ErrorForbidden("login error"))?;

    thread::sleep(time::Duration::from_secs(1));

    let pool = &data.db_pool;
    let channels = query_channels(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    let mut response = Vec::new();
    for ch_id in channels {
        let last_id = query_have_read(pool, user_id, ch_id)
            .await
            .map_err(|e| error::ErrorInternalServerError(e))?;

        let cnt = if last_id > 0 {
            sqlx::query_as::<_, (i64,)>(
                "SELECT COUNT(*) as cnt FROM message WHERE channel_id = ? AND ? < id",
            )
                .bind(ch_id)
                .bind(last_id)
        } else {
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) AS cnt FROM message WHERE channel_id = ?")
                .bind(ch_id)
        }
        .fetch_one(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?
        .0;
        response.push(UnreadNum {
            channel_id: ch_id,
            unread: cnt,
        });
    }
    Ok(HttpResponse::Ok().json(response))
}

#[derive(Deserialize)]
struct QueryPage {
    page: Option<i64>,
}

async fn get_history(
    session: Session,
    data: web::Data<Context>,
    query: web::Query<QueryPage>,
    path_info: web::Path<(u64,)>,
) -> Result<HttpResponse> {
    let user = ensure_login(&data, session)
        .await
        .ok_or(error::ErrorForbidden("login error."))?;

    let channel_id = path_info.0;
    let page = query.page.unwrap_or(1);
    if page < 1 {
        return Err(error::ErrorBadRequest("page is smaller than 1."));
    }

    let n = 20;
    let pool = &data.db_pool;
    let cnt =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) AS cnt FROM message WHERE channel_id = ?")
            .bind(channel_id)
            .fetch_one(pool)
            .await
            .map_err(|e| error::ErrorInternalServerError(e))?
            .0;
    let mut max_page = (cnt + n - 1) / n;
    if max_page == 0 {
        max_page = 1;
    }

    if page > max_page {
        return Err(error::ErrorBadRequest("page is bigger than max_page."));
    }

    let messages = sqlx::query_as::<_, Message>(
        "SELECT * FROM message WHERE channel_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(channel_id)
    .bind(n)
    .bind((page - 1) * n)
    .fetch_all(pool)
    .await
    .map_err(|e| error::ErrorInternalServerError(e))?;

    let num_messages = messages.len();
    let mut mjson = Vec::new();
    for i in (0..num_messages).rev() {
        let message = &messages[i];
        let smessage = jsonify_message(pool, message).await;
        mjson.push(smessage);
    }

    let channels = sqlx::query_as::<_, ChannelInfo>("SELECT * FROM channel ORDER BY id")
        .fetch_all(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    let mut ctx = tera::Context::new();
    ctx.insert("channel_id", &channel_id);
    ctx.insert("channels", &channels);
    ctx.insert("messages", &mjson);
    ctx.insert("max_page", &max_page);
    ctx.insert("page", &page);
    ctx.insert("user", &user);

    render(&data.templates, Some(ctx), "history.html")
}

// GET /profile/:user_name
async fn get_profile(
    session: Session,
    data: web::Data<Context>,
    path: web::Path<(String,)>,
) -> Result<HttpResponse> {
    let user = ensure_login(&data, session)
        .await
        .ok_or(error::ErrorForbidden("login error"))?;

    let pool = &data.db_pool;
    let channels = sqlx::query_as::<_, ChannelInfo>("SELECT * FROM channel ORDER BY id")
        .fetch_all(pool)
        .await
        .map_err(|e| error::ErrorInternalServerError(e))?;

    let user_name = &path.0;
    let other = sqlx::query_as::<_, User>("SELECT * FROM user WHERE name = ?")
        .bind(user_name)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => error::ErrorNotFound("required user not found."),
            _ => error::ErrorInternalServerError(e),
        })?;

    let mut ctx = tera::Context::new();
    ctx.insert("channel_id", &0);
    ctx.insert("channels", &channels);
    ctx.insert("user", &user);
    ctx.insert("other", &other);
    ctx.insert("self_profile", &(user.id == other.id));

    render(&data.templates, Some(ctx), "profile.html")
}

#[get("add_channel")]
async fn get_add_channel(data: web::Data<Context>, session: Session) -> Result<HttpResponse> {
    let pool = &data.db_pool;

    let user = ensure_login(&data, session).await.ok_or(redirect_to("/"))?;

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

    ensure_login(&data, session).await.ok_or(redirect_to("/"))?;

    let name = &form.name;
    let desc = &form.description;

    if name.is_empty() || desc.is_empty() {
        return Err(error::ErrorBadRequest("channel form is empty"));
    }

    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO channel (name, description, updated_at, created_at) VALUES (?, ?, NOW(), NOW())"
    )
    .bind(name)
    .bind(desc)
    .execute(&mut tx)
    .await.map_err(|e| error::ErrorInternalServerError(e))?;
    let last_id = sqlx::query_as::<_, (u64,)>("SELECT LAST_INSERT_ID()")
        .fetch_one(&mut tx)
        .await
        .unwrap()
        .0;
    tx.commit().await.unwrap();
    Ok(redirect_to(&format!("/channel/{}", last_id)))
}

#[post("profile")]
async fn post_profile(
    session: Session,
    data: web::Data<Context>,
    mut payload: Multipart,
) -> Result<HttpResponse> {
    let user = ensure_login(&data, session)
        .await
        .ok_or(error::ErrorForbidden("login error"))?;
    let uid = user.id;

    let pool = &data.db_pool;
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_type = field.content_disposition().unwrap();

        match content_type.get_name().unwrap() {
            "display_name" => {
                let data = field.next().await.unwrap().unwrap();
                let name = String::from_utf8(data.to_vec()).unwrap();
                sqlx::query("UPDATE user SET display_name = ? WHERE id = ?")
                    .bind(name)
                    .bind(uid)
                    .execute(pool)
                    .await
                    .map_err(|e| error::ErrorInternalServerError(e))?;
            }
            "avatar_icon" => {
                let file_name = content_type.get_filename().unwrap();
                let ext = path::Path::new(file_name)
                    .extension()
                    .and_then(ffi::OsStr::to_str)
                    .unwrap();
                if !["jpg", "jpeg", "png", "gif"].contains(&ext) {
                    return Err(error::ErrorBadRequest("file extension is not valid."));
                }
                let data = field.next().await.unwrap().unwrap().to_vec();
                if data.len() > AVATAR_MAX_BYTES {
                    return Err(error::ErrorBadRequest("posted img size is too big."));
                }

                let mut hasher = Sha1::new();
                hasher.input(&data);
                let hex = hasher.result_str();

                let avatar_name = format!("{}.{}", hex, ext);
                if !avatar_name.is_empty() && data.len() > 0 {
                    sqlx::query("INSERT INTO image (name, data) VALUES (?, ?)")
                        .bind(&avatar_name)
                        .bind(data)
                        .execute(pool)
                        .await
                        .and(
                            sqlx::query("UPDATE user SET avatar_icon = ? WHERE id = ?")
                                .bind(&avatar_name)
                                .bind(uid)
                                .execute(pool)
                                .await,
                        )
                        .map_err(|e| error::ErrorInternalServerError(e))?;
                }
            }
            _ => {}
        }
    }
    Ok(redirect_to("/"))
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct Image {
    name: String,
    data: Vec<u8>,
}

// GET /icons/:file_name
async fn get_icon(data: web::Data<Context>, path: web::Path<(String,)>) -> Result<HttpResponse> {
    let pool = &data.db_pool;
    let file_name = &path.0;
    let img = sqlx::query_as::<_, Image>("SELECT name, data FROM image WHERE name = ?")
        .bind(file_name)
        .fetch_one(pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => error::ErrorNotFound("image not found."),
            e => error::ErrorInternalServerError(e),
        })?;

    let ext = path::Path::new(&img.name)
        .extension()
        .and_then(ffi::OsStr::to_str)
        .unwrap();

    let mime = match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        _ => return Err(error::ErrorNotFound("requested image not found.")),
    };

    Ok(HttpResponse::Ok().content_type(mime).body(img.data))
}

#[derive(Deserialize)]
struct QueryMessage {
    channel_id: i64,
    last_message_id: i64,
}

#[derive(Serialize, Deserialize)]
struct ServiceMessage {
    id: i64,
    user: User,
    date: String,
    content: String,
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
struct Message {
    id: i64,
    channel_id: i64,
    user_id: i64,
    content: String,
    created_at: NaiveDateTime,
}

fn redirect_to(path: &str) -> HttpResponse {
    HttpResponse::build(StatusCode::SEE_OTHER)
        .header(header::LOCATION, path)
        .finish()
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    env_logger::init();

    // database connection
    let database_url =
        "mysql://isucon:isucon@127.0.0.1:3306/isubata?parseTime=true&loc=Local&charset=utf8mb4";
    let pool = MySqlPool::builder()
        .max_size(5) // maximum number of connections in the pool
        .build(&database_url)
        .await
        .unwrap();

    HttpServer::new(move || {
        // static ディレクトリを指定して, Teraを初期化
        let templates = Tera::new("views/*").unwrap();

        App::new()
            .data(Context {
                db_pool: pool.clone(),
                templates: templates.clone(),
            })
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            // enable logger - always register actix-web Logger middleware last
            .wrap(middleware::Logger::default())
            .service(get_initialize)
            .service(get_index)
            .service(get_register)
            .service(post_register)
            .service(get_login)
            .service(post_login)
            .service(get_logout)
            .service(web::resource("/channel/{channel_id}").route(web::get().to(get_channel)))
            .service(get_message)
            .service(post_message)
            .service(fetch_unread)
            .service(web::resource("/history/{channel_id}").route(web::get().to(get_history)))
            .service(web::resource("/profile/{user_name}").route(web::get().to(get_profile)))
            .service(post_profile)
            .service(get_add_channel)
            .service(post_add_channel)
            .service(web::resource("/icons/{file_name}").route(web::get().to(get_icon)))
            // static files
            .service(fs::Files::new("", "../public").show_files_listing())
    })
    .bind("127.0.0.1:5000")?
    .run()
    .await
}
