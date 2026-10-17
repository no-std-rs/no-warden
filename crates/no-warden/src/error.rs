use core::fmt;
use serde::Serialize;

/// Stable errors that an HTTP adapter can translate without inspecting storage errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiError {
    pub kind: ErrorKind,
    pub message: &'static str,
    pub field: Option<&'static str>,
}

impl ApiError {
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            field: None,
        }
    }

    pub const fn invalid(field: &'static str, message: &'static str) -> Self {
        Self {
            kind: ErrorKind::InvalidRequest,
            message,
            field: Some(field),
        }
    }

    pub const fn status_code(self) -> u16 {
        match self.kind {
            ErrorKind::InvalidRequest => 400,
            ErrorKind::Unauthorized => 401,
            ErrorKind::Forbidden => 403,
            ErrorKind::NotFound => 404,
            ErrorKind::Conflict => 409,
            ErrorKind::Storage => 500,
        }
    }

    pub const fn response(self) -> ErrorResponse {
        ErrorResponse {
            object: "error",
            message: self.message,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl core::error::Error for ApiError {}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub object: &'static str,
    pub message: &'static str,
}
