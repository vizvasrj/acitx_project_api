use std::{format, println};

use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{get, post, web, App, Error, Either, HttpResponse, HttpServer, Responder, Result, error, HttpRequest, http::header::ContentType};
use futures::{future::ok, stream::once};
use std::sync::Mutex;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Deserialize, Serialize};
use serde_json;
use derive_more::{Display, Error};
use log::{info, warn, error as log_error, debug};
use actix_web::middleware::Logger;
struct AppState {
    app_name: String,
}

struct AppStateWithCounter {
    counter: Mutex<i32>,
}

#[get("/")]
async fn hello(data: web::Data<AppState>) -> String {
    let app_name = &data.app_name;
    format!("Hello {app_name}!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello(data: web::Data<AppStateWithCounter>) -> String {
    let mut counter = data.counter.lock().unwrap();
    *counter += 1;
    format!("Request number: {counter}")
}

fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/test")
            .route(web::get().to(|| async {HttpResponse::Ok().body("test")}))
            .route(web::head().to(HttpResponse::MethodNotAllowed)),
    );
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/app")
            .route(web::get().to(|| async {HttpResponse::Ok().content_type(ContentType::json()).body("{\"app\": \"one\"}")})) 
            .route(web::head().to(HttpResponse::MethodNotAllowed)),
    );
}

#[get("/users/{user_id}/{friend}")]
async fn index(path: web::Path<(u32, String)>) -> Result<String> {
    let (user_id, friend) = path.into_inner();
    Ok(format!("Welcome {} user_id {}!", friend, user_id))
}

#[derive(Debug,Deserialize)]
struct Info {
    username: String,
}

#[post("/submit")]
async fn submit(info: web::Json<Info>) -> Result<String> {
    Ok(format!{"Welcome {}!", info.username})
}

#[post("/form")]
async fn form(info: web::Form<Info>) -> Result<String> {
    Ok(format!{"Welcome {}!", info.username})
}

#[derive(Clone)]
struct MyAppState {
    local_count: Cell<usize>,
    global_count: Arc<AtomicUsize>,
}

// async fn show_count(data: web::Data<MyAppState>) -> impl Responder {
//     format!("count {}", data.count.get())
// }

async fn add_one(data: web::Data<MyAppState>) -> impl Responder {
    data.global_count.fetch_add(1, Ordering::Relaxed);

    let local_count = data.local_count.get();
    data.local_count.set(local_count + 1);
    format!("1:local_count: {}\n   2:global_count: {}", data.local_count.get(), data.global_count.load(Ordering::Relaxed))
}

// async fn ass_one(data:)

async fn hello_world(_req: HttpRequest) -> String {
    "hwllo world".to_string()
}

#[derive(Serialize, Debug)]
struct MyObj {
    name: &'static str,
}

impl Responder for MyObj {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();
        println!("{}", body);

        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(body)
    }
}

async fn my_obj() -> impl Responder {
    MyObj {name: "somename?"}
}

#[get("/stream")]
async fn stream() -> HttpResponse {
    let body = once(ok::<_, Error>(web::Bytes::from_static(b"test")));
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .streaming(body)
}


type RegisterResult = Either<HttpResponse, Result<&'static str, Error>>;

async fn variant() -> RegisterResult {
    if true {
        // Chose Left variant
        Either::Left(HttpResponse::BadRequest().body("Bad data"))
    } else {
        // Chose right variant
        Either::Right(Ok("Hello"))
    }
}

// advanced Actix
// * Error

#[derive(Debug, Display, Error)]
#[display(fmt="my error: {}", name)]
struct MyError {
    name: &'static str,
}

impl error::ResponseError for MyError {}

async fn some_error() -> Result<&'static str, MyError> {
    Err(MyError { name: "some custome error" })
}

#[derive(Debug, Display, Error)]
enum MyEnumError {
    #[display(fmt="internal error")]
    InternalError,

    #[display(fmt="bad request")]
    BadClientData,

    #[display(fmt="timeout")]
    Timeout,
}

impl error::ResponseError for MyEnumError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            MyEnumError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            MyEnumError::BadClientData => StatusCode::BAD_REQUEST,
            MyEnumError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

#[get("/some_enum_error")]
async fn some_enum_error() -> Result<&'static str, MyEnumError> {
    Err(MyEnumError::BadClientData)
}



// #[derive(Debug, Display, Error)]
// enum UserError {
//     #[display(fmt = "An internal error occurred. Please try again later.")]
//     InternalError,
// }

// impl error::ResponseError for UserError {
//     fn error_response(&self) -> HttpResponse {
//         HttpResponse::build(self.status_code())
//             .insert_header(ContentType::html())
//             .body(self.to_string())
//     }

//     fn status_code(&self) -> StatusCode {
//         match *self {
//             UserError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
//         }
//     }
// }

// * log
#[get("/user_error")]
async fn user_error() -> Result<&'static str, MyEnumError> {
    info!("success log");
    debug!("debug log");
    warn!("Connected to port {} at {} Mb/s", 5, 8);
    log_error!(target: "connection_events", "Successfull connection, port: {}, speed: {}",
      5, 8);
    println!("??");
    do_thing_that_fails().map_err(|_e| MyEnumError::InternalError)?;
    Ok("success!")
}

fn do_thing_that_fails() -> std::result::Result<(), String> {
    if true {
        return Ok(());
    }
    return Err("Some error".to_string())
}



#[rustfmt::skip]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Stated web");
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    let counter = web::Data::new(AppStateWithCounter {
        counter: Mutex::new(0_i32)
    });

    let data = MyAppState {
        local_count: Cell::new(0_usize),
        global_count: Arc::new(AtomicUsize::new(0))
    };

    HttpServer::new(move || {
        let logger = Logger::default();

        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(|err, _req| {
                // create custom error response
                println!("{:?}", _req.path().to_string());
                error::InternalError::from_response(err, HttpResponse::Conflict().finish())
                    .into()
            });

        App::new()
            .wrap(logger)
            .app_data(web::Data::new(AppState {
                app_name: String::from("My State storage?"),
            }))
            .app_data(counter.clone())
            .app_data(web::Data::new(data.clone()))
            .app_data(json_config)
            .configure(config)
            .service(web::scope("/api").configure(scoped_config))
            .route("/add", web::to(add_one))
            .service(hello)
            .service(echo)
            .service(index)
            .service(submit)
            .service(form) 
            .service(stream)
            .service(some_enum_error)
            .service(user_error)
            .route("/hello_world", web::get().to(hello_world))
            .route("/hey", web::get().to(manual_hello))
            .route("/my_obj", web::get().to(my_obj))
            .route("/variant", web::get().to(variant))
            .route("/some_error", web::get().to(some_error))
    })
        .bind(("127.0.0.1", 8080))
        .unwrap()
        .workers(1)
        .run()
        .await
}

