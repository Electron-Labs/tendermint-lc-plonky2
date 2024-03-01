use tracing_appender::{non_blocking::WorkerGuard, rolling::hourly};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn initialize_logger() -> WorkerGuard {

    let file_appender = hourly("./log", "multithreaded-fs.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::layer().with_writer(non_blocking).json().pretty();

    let stdout_log = tracing_subscriber::fmt::layer().compact();
    tracing_subscriber::registry().with(stdout_log).with(file_layer).init();
    _guard
}
