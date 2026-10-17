use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {0}")]
    Read(#[from] std::io::Error),
    #[error("Invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Invalid value for {name}: {value}")]
    InvalidValue { name: String, value: String },
    #[error("Environment variable {0} is not valid Unicode")]
    InvalidEnvironment(String),
    #[error("Expected --config <path>")]
    MissingConfigPath,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[default]
    Standalone,
    Distributed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub sqlite_path: PathBuf,
    pub postgres_url: Option<String>,
    pub redis_url: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            sqlite_path: PathBuf::from("corvus.db"),
            postgres_url: None,
            redis_url: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SensorConfig {
    pub native_enabled: bool,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mode: RunMode,
    pub storage: StorageConfig,
    pub sensor: SensorConfig,
    pub bind_address: String,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: RunMode::Standalone,
            storage: StorageConfig::default(),
            sensor: SensorConfig::default(),
            bind_address: "0.0.0.0:8080".into(),
            log_level: "info".into(),
        }
    }
}

impl Config {
    pub fn from_args() -> Result<Self, ConfigError> {
        let mut args = std::env::args().skip(1);
        let mut config_path = PathBuf::from("corvus.toml");
        while let Some(arg) = args.next() {
            if arg == "--config" {
                config_path = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or(ConfigError::MissingConfigPath)?;
            } else {
                return Err(ConfigError::InvalidValue {
                    name: "argument".into(),
                    value: arg,
                });
            }
        }
        Self::from_file(config_path)
    }

    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let mut config = match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(err) => return Err(err.into()),
        };

        config.apply_environment()?;
        Ok(config)
    }

    fn apply_environment(&mut self) -> Result<(), ConfigError> {
        if let Some(value) = env_value("CORVUS_MODE")? {
            self.mode = match value.to_ascii_lowercase().as_str() {
                "standalone" => RunMode::Standalone,
                "distributed" => RunMode::Distributed,
                _ => {
                    return Err(ConfigError::InvalidValue {
                        name: "CORVUS_MODE".into(),
                        value,
                    })
                }
            };
        }
        if let Some(value) = env_value("CORVUS_BIND_ADDRESS")? {
            self.bind_address = value;
        }
        if let Some(value) = env_value("CORVUS_LOG_LEVEL")? {
            self.log_level = value;
        }
        if let Some(value) = env_value("CORVUS_STORAGE_SQLITE_PATH")? {
            self.storage.sqlite_path = PathBuf::from(value);
        }
        if let Some(value) = env_value("CORVUS_STORAGE_REDIS_URL")? {
            self.storage.redis_url = Some(value);
        }
        if let Some(value) = env_value("CORVUS_STORAGE_POSTGRES_URL")? {
            self.storage.postgres_url = Some(value);
        }
        if let Some(value) = env_value("CORVUS_SENSOR_NATIVE_ENABLED")? {
            self.sensor.native_enabled = value.parse().map_err(|_| ConfigError::InvalidValue {
                name: "CORVUS_SENSOR_NATIVE_ENABLED".into(),
                value,
            })?;
        }
        if let Some(value) = env_value("CORVUS_SENSOR_HOSTNAME")? {
            self.sensor.hostname = Some(value);
        }
        Ok(())
    }
}

fn env_value(name: &str) -> Result<Option<String>, ConfigError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(ConfigError::InvalidEnvironment(name.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_toml_configuration() {
        let config: Config = toml::from_str(
            r#"
                mode = "standalone"
                bind_address = "127.0.0.1:9000"
                [storage]
                sqlite_path = "test.db"
                [sensor]
                native_enabled = true
            "#,
        )
        .expect("valid config");

        assert_eq!(config.mode, RunMode::Standalone);
        assert_eq!(config.bind_address, "127.0.0.1:9000");
        assert_eq!(config.storage.sqlite_path, PathBuf::from("test.db"));
        assert!(config.sensor.native_enabled);
    }

    #[test]
    fn missing_config_file_uses_standalone_defaults() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment test lock");
        let names = [
            "CORVUS_MODE",
            "CORVUS_BIND_ADDRESS",
            "CORVUS_LOG_LEVEL",
            "CORVUS_STORAGE_SQLITE_PATH",
            "CORVUS_STORAGE_REDIS_URL",
            "CORVUS_STORAGE_POSTGRES_URL",
            "CORVUS_SENSOR_NATIVE_ENABLED",
            "CORVUS_SENSOR_HOSTNAME",
        ];
        let old_values: Vec<_> = names
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        for name in names {
            std::env::remove_var(name);
        }

        let config = Config::from_file("no-such-corvus-config.toml").expect("default config");
        for (name, value) in old_values {
            if let Some(value) = value {
                std::env::set_var(name, value);
            }
        }
        assert_eq!(config.mode, RunMode::Standalone);
        assert_eq!(config.bind_address, "0.0.0.0:8080");
    }

    #[test]
    fn environment_overrides_mode() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment test lock");
        let original = std::env::var_os("CORVUS_MODE");
        std::env::set_var("CORVUS_MODE", "distributed");
        let mut config = Config::default();
        let result = config.apply_environment();
        match original {
            Some(value) => std::env::set_var("CORVUS_MODE", value),
            None => std::env::remove_var("CORVUS_MODE"),
        }

        result.expect("valid environment override");
        assert_eq!(config.mode, RunMode::Distributed);
    }
}
