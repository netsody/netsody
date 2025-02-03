pub fn get_env<T: std::str::FromStr>(key: &str, default: T) -> T
where
    T::Err: std::fmt::Debug,
{
    std::env::var(format!("DRASYL_{key}"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
