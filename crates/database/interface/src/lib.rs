//! Optimism-specific constants, types, and helpers.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc as std;

#[cfg(feature = "asyncdb")]
pub mod async_db;
pub mod db;
pub mod db_ref;
pub mod empty_db;
pub mod error;

#[cfg(feature = "asyncdb")]
pub use async_db::{DatabaseAsync, WrapDatabaseAsync};
pub use db::{Database, DatabaseCommit};
pub use db_ref::{DatabaseRef, WrapDatabaseRef};
pub use empty_db::{EmptyDB, EmptyDBTyped};
pub use error::DBErrorMarker;
