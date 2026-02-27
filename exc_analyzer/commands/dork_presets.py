PRESETS = {
    "secrets": [
        "filename:.env",
        "filename:id_rsa",
        "filename:id_dsa",
        "filename:id_ed25519",
        "filename:*.pem",
        "filename:*.key",
        "filename:secrets.json",
        "filename:deployment-config.json"
    ],
    "config": [
        "filename:wp-config.php",
        "filename:config.php",
        "filename:config.json",
        "filename:settings.py",
        "filename:database.yml",
        "filename:settings.json",
        "filename:Web.config"
    ],
    "actions": [
        "filename:main.yml path:.github/workflows",
        "filename:deploy.yml path:.github/workflows",
        "filename:release.yml path:.github/workflows",
        "filename:ci.yml path:.github/workflows"
    ],
    "aws": [
        "filename:.aws/credentials",
        "filename:.aws/config",
        "AKIAIOSFODNN7EXAMPLE",
        "aws_access_key_id",
        "aws_secret_access_key"
    ],
    "azure": [
        "azure_storage_account",
        "azure_storage_access_key",
        "filename:azureProfile.json"
    ],
    "google": [
        "filename:client_secret.json",
        "filename:service_account.json",
        "GOOGLE_APPLICATION_CREDENTIALS"
    ]
}
def get_preset_choices():
    return list(PRESETS.keys())
