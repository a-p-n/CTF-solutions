//// Various helper functions for use in the web interface of the application.
////

import gleam/http.{Http}
import gleam/http/cookie
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleamering_hope/database
import gleamering_hope/error.{type AppError}
import wisp.{type Request, type Response}

pub type Context {
  Context(db: database.Connection, user_id: Int)
}

pub const uid_cookie = "uid"

/// Load the user from the `uid` cookie if set, otherwise create a new user row
/// and assign that in the response cookies.
///
/// The `uid` cookie is signed to prevent tampering.
///
pub fn authenticate(
  req: Request,
  ctx: Context,
  next: fn(Context) -> Response,
) -> Response {
  let id =
    wisp.get_cookie(req, uid_cookie, wisp.Signed)
    |> result.try(int.parse)
    |> option.from_result

  let id = case id {
    option.None -> 0
    option.Some(id) -> id
  }
  let context = Context(..ctx, user_id: id)
  let resp = next(context)
  resp
}

pub type AppResult =
  Result(Response, AppError)

pub fn result_to_response(result: AppResult) -> Response {
  case result {
    Ok(response) -> response
    Error(error) -> error_to_response(error)
  }
}

pub fn try_(result: Result(t, AppError), next: fn(t) -> Response) -> Response {
  case result {
    Ok(t) -> next(t)
    Error(error) -> error_to_response(error)
  }
}

/// Return an appropriate HTTP response for a given error.
///
pub fn error_to_response(error: AppError) -> Response {
  case error {
    error.UserNotFound -> user_not_found()
    error.NotFound -> wisp.not_found()
    error.MethodNotAllowed -> wisp.method_not_allowed([])
    error.BadRequest -> wisp.bad_request()
    error.UnprocessableEntity | error.ContentRequired ->
      wisp.unprocessable_entity()
    error.SqlightError(_) -> wisp.internal_server_error()
  }
}

pub fn user_not_found() -> Response {
  let attributes =
    cookie.Attributes(..cookie.defaults(Http), max_age: option.Some(0))
  wisp.not_found()
  |> response.set_cookie("uid", "", attributes)
}

pub fn key_find(list: List(#(k, v)), key: k) -> Result(v, AppError) {
  list
  |> list.key_find(key)
  |> result.replace_error(error.UnprocessableEntity)
}

pub fn parse_int(string: String) -> Result(Int, AppError) {
  string
  |> int.parse
  |> result.replace_error(error.BadRequest)
}

pub fn require_ok(t: Result(t, AppError), next: fn(t) -> Response) -> Response {
  case t {
    Ok(t) -> next(t)
    Error(error) -> error_to_response(error)
  }
}
