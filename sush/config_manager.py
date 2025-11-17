"""
Configuration management for sushCore.

Supports config files and environment variables for deployment flexibility.
"""

import os
import configparser
from typing import Dict, Any, Optional
from pathlib import Path


class SushConfig:
    """Configuration manager with environment variable support."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = configparser.ConfigParser()
        self.config_loaded = False
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """Load configuration from file."""
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        
        self.config.read(config_file)
        self.config_loaded = True
    
    def get(self, section: str, key: str, default: Any = None, env_var: Optional[str] = None) -> Any:
        """Get config value with environment variable override."""
        # Check environment variable first
        if env_var and env_var in os.environ:
            return os.environ[env_var]
        
        # Fallback to config file
        if self.config_loaded and self.config.has_option(section, key):
            return self.config.get(section, key)
        
        # Return default
        return default
    
    def get_int(self, section: str, key: str, default: int = 0, env_var: Optional[str] = None) -> int:
        """Get integer config value."""
        value = self.get(section, key, default, env_var)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, section: str, key: str, default: bool = False, env_var: Optional[str] = None) -> bool:
        """Get boolean config value."""
        value = self.get(section, key, default, env_var)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return default
    
    def validate_required(self, required_configs: Dict[str, str]):
        """Validate that required configurations are present."""
        missing = []
        for section_key, description in required_configs.items():
            section, key = section_key.split('.')
            if not self.get(section, key):
                missing.append(f"{section_key} ({description})")
        
        if missing:
            raise ValueError("Missing required configuration:\n" + "\n".join(missing))


# Default configurations
DEFAULT_CLIENT_CONFIG = {
    'network.listen_port': ('8080', 'SUSHCORE_LISTEN_PORT'),
    'network.server_host': ('127.0.0.1', 'SUSHCORE_SERVER_HOST'),
    'network.server_port': ('9090', 'SUSHCORE_SERVER_PORT'),
    'security.threat_level': ('medium', 'SUSHCORE_THREAT_LEVEL'),
    'ml.enable_detection': ('true', 'SUSHCORE_ML_ENABLE'),
}

DEFAULT_SERVER_CONFIG = {
    'network.bind_address': ('0.0.0.0', 'SUSHCORE_BIND_ADDR'),
    'network.bind_port': ('9090', 'SUSHCORE_BIND_PORT'),
    'security.require_auth': ('false', 'SUSHCORE_REQUIRE_AUTH'),
    'logging.level': ('INFO', 'SUSHCORE_LOG_LEVEL'),
}


def load_client_config(config_file: str = 'config/client.conf') -> SushConfig:
    """Load client configuration with defaults."""
    config = SushConfig(config_file)
    
    # Validate required configs
    required = {
        'network.server_host': 'sushCore server hostname',
        'network.server_port': 'sushCore server port'
    }
    config.validate_required(required)
    
    return config


def load_server_config(config_file: str = 'config/server.conf') -> SushConfig:
    """Load server configuration with defaults."""
    config = SushConfig(config_file)
    return config
