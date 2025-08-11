# config/settings.py
import json
import os

class Settings:
    def __init__(self):
        self.config_file = "config/punyhunter_config.json"
        self.default_config = {
            "attack_settings": {
                "max_threads": 10,
                "request_delay": 1.0,
                "timeout": 10,
                "retry_attempts": 3
            },
            "evasion_settings": {
                "use_proxies": True,
                "rotate_user_agents": True,
                "randomize_headers": True,
                "use_tor": False
            },
            "database_settings": {
                "mysql": {
                    "host": "localhost",
                    "port": 3306,
                    "user": "root",
                    "password": "",
                    "database": "test"
                },
                "postgresql": {
                    "host": "localhost",
                    "port": 5432,
                    "user": "postgres",
                    "password": "",
                    "database": "test"
                }
            },
            "output_settings": {
                "save_results": True,
                "output_format": ["json", "csv", "pdf"],
                "output_directory": "results/"
            },
            "notification_settings": {
                "slack_webhook": "",
                "discord_webhook": "",
                "email_notifications": False
            }
        }
        
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self.default_config
            self.save_config()
            
    def save_config(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
