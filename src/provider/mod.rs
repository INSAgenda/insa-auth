mod login;
mod validate;
pub use login::*;
pub use validate::*;
use crate::*;

use rocket::tokio::sync::RwLock;
use std::{collections::HashMap, sync::LazyLock};

static TICKETS: LazyLock<RwLock<HashMap<String, (u64, String, Claims)>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});
