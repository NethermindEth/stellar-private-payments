use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, output, unlock};

/// `spp password change`: seal the local database's key with a new password.
pub fn change(config: &CliConfig, new_password_file: Option<&Path>, json: bool) -> Result<()> {
    let database = config.db_path();
    unlock::change_password(
        &database,
        config.password_file.as_deref(),
        new_password_file,
    )?;
    if json {
        #[derive(Serialize)]
        struct Changed {
            database: String,
            password_changed: bool,
        }
        return output::emit(
            &Changed {
                database: database.display().to_string(),
                password_changed: true,
            },
            true,
        );
    }
    println!("Password changed for {}.", database.display());
    Ok(())
}
