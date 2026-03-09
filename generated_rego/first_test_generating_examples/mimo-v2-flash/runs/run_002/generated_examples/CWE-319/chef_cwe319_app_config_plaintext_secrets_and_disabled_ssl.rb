# Chef recipe to write an application configuration file with plaintext secrets
# and explicitly disabled SSL for database connection.

file '/etc/mywebapp/config.json' do
  content <<-EOF
{
  "database": {
    "host": "mydb.example.com",
    "port": 5432,
    "username": "appuser",
    "password": "my_super_secret_db_password",
    "ssl_mode": "disable" # CWE-319: Explicitly disabling SSL for DB connection.
  },
  "api_key": "plain_text_api_key_12345", # CWE-319: Hardcoded plaintext API key.
  "service_endpoint": "http://legacy-service.example.com/api" # CWE-319: Using HTTP endpoint.
}
EOF
  mode '0640'
  owner 'mywebapp'
  group 'mywebapp'
  # CWE-319: Hardcoded sensitive information (password, API key) stored in a plaintext configuration file.
end
