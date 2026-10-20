use std::str::FromStr;
use std::time::Duration;

use log::LevelFilter;
use sqlx::ConnectOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

// 参数沿用 sfo-sql 0.4 `SqlPool::open(uri, 5, None)` 的取值，不设 journal_mode。
pub(crate) async fn open_sqlite_pool(uri: &str) -> Result<SqlitePool, sqlx::Error> {
    log::info!("open sqlite pool {}", uri);
    let pool_options = SqlitePoolOptions::new()
        .max_connections(5)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(300))
        .idle_timeout(Duration::from_secs(300));
    #[allow(unused_mut)]
    let mut options = SqliteConnectOptions::from_str(uri)?
        .busy_timeout(Duration::from_secs(300))
        .create_if_missing(true);
    #[cfg(target_os = "ios")]
    {
        options = options.serialized(true);
    }
    let options = options
        .log_statements(LevelFilter::Off)
        .log_slow_statements(LevelFilter::Off, Duration::from_secs(10));
    pool_options.connect_with(options).await
}
