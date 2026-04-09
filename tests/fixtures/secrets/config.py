# Fake Python config for TruffleHog detection testing
# These are NOT real secrets — they are test fixtures

import os

# Hardcoded API keys (bad practice — should use env vars)
OPENAI_API_KEY = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
ANTHROPIC_API_KEY = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
SLACK_WEBHOOK = "https://hooks.example.com/services/TXXXXXXXXX/BXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX"

# Database credentials
DB_HOST = "db.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
