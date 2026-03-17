package glitch

import data.glitch_lib
import future.keywords.in

password_keywords := {
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "api_key",
    "access_key",
    "client_secret",
    "auth_token",
    "db_password",
    "admin_password",
    "root_password",
    "credential",
    "login",
    "user_password",
    "passphrase",
    "token_value",
    "authorization",
    "pwd",
    "pass",
    "auth",
    "credentials",
    "conn_str",
    "connection_string",
    "passwd_hash",
    "hash",
    "crypt",
    "shadow",
    "passcode",
    "auth_key",
    "api_secret",
    "private_key",
    "certificate",
    "pem",
    "ssh_key",
    "db_conn",
    "db_secret",
    "db_passwords",
    "password_hash",
    "db_key",
    "db_user",
    "db_name",
    "db_host",
    "db_port",
    "db_ssl",
    "db_repl",
    "db_max_conn",
    "db_timeout",
    "db_username",
    "db_password",
    "database_url",
    "db_uri",
    "auth_password",
    "token_secret",
    "api_key_secret"
}

common_default_passwords := {
    "password",
    "changeme",
    "default",
    "test",
    "123456",
    "admin",
    "tiger",
    "root",
    "user",
    "superuser",
    "letmein",
    "abc123",
    "12345678",
    "password123",
    "welcome",
    "monkey",
    "qwert",
    "fallback",
    "secret",
    "1234",
    "pass",
    "123",
    "admin123",
    "password1",
    "changeit",
    "test123",
    "123qwe",
    "1234567",
    "123456789",
    "welcome123",
    "abc123456",
    "password123456",
    "adminadmin",
    "password456",
    "password@123",
    "password12345678",
    "welcome123456",
    "123456pass",
    "adminpass",
    "letmein123",
    "testpass",
    "password1234",
    "change123",
    "password000",
    "defaultpass",
    "pass1234",
    "password12345",
    "secret123",
    "passw0rd",
    "admin1234",
    "user123",
    "pass123",
    "password123456",
    "testtest",
    "123123",
    "pass123",
    "password123!",
    "pass12345",
    "password1234567",
    "1234567890",
    "password123456789",
    "welcome1234567",
    "password1234567890",
    "adminpassword",
    "changeme123",
    "default123",
    "test123",
    "root123",
    "user123",
    "superuser123",
    "password12345678",
    "test123456",
    "secret123456",
    "admin123456",
    "password12345678901",
    "password123456789012",
    "password1234567890123",
    "password12345678901234",
    "password123456789012345",
    "password1234567890123456",
    "password12345678901234567"
}

is_password_field(name) {
    name in password_keywords
} else {
    name == "connection_string"
} else {
    name == "credentials"
} else {
    name == "auth"
} else {
    name == "login"
} else {
    name == "username"
} else {
    name == "endpoint"
} else {
    name == "service_account_key"
} else {
    name == "database_password"
} else {
    name == "db_key"
} else {
    name == "db_secret"
} else {
    name == "db_conn"
} else {
    name == "db_passwords"
} else {
    name == "password_hash"
} else {
    name == "hash"
} else {
    name == "crypt"
} else {
    name == "shadow"
} else {
    name == "passcode"
} else {
    name == "auth_key"
} else {
    name == "api_secret"
} else {
    name == "private_key"
} else {
    name == "certificate"
} else {
    name == "pem"
} else {
    name == "ssh_key"
} else {
    name == "db_conn"
} else {
    name == "db_secret"
} else {
    name == "db_passwords"
} else {
    name == "password_hash"
} else {
    name == "db_key"
} else {
    name == "db_user"
} else {
    name == "db_name"
} else {
    name == "db_host"
} else {
    name == "db_port"
} else {
    name == "db_ssl"
} else {
    name == "db_repl"
} else {
    name == "db_max_conn"
} else {
    name == "db_timeout"
} else {
    name == "db_username"
} else {
    name == "db_password"
} else {
    name == "database_url"
} else {
    name == "db_uri"
} else {
    name == "auth_password"
} else {
    name == "token_secret"
} else {
    name == "api_key_secret"
}

is_hardcoded_value(value) {
    value.ir_type == "String"
    value.value != ""
    value.value != "null"
    value.value != "none"
    value.value != "undefined"
    value.value != "0"
    value.value != "false"
    value.value != "true"
    value.value != "null"
    value.value != "nil"
    value.value != ""
    not is_variable_or_reference(value)
    not regex.match("(?i)^\\s*\\{\\{.*\\}\\}", value.value)
    not regex.match("(?i)^\\s*\\!Ref\\s*|\\!ImportValue\\s*|\\!GetAtt\\s*", value.value)
    not regex.match("(?i)^\\s*(?:ref|secret|ssm|parameter|kms|vault|secretsmanager|aws|gcp|azure|var|env|lookup|get|fetch|include|require|template|remote|file|lookup_file|parse_yaml|merge|deep_merge|from_file|config|config_file|get_secret|get_parameter|lookup_secret|lookup_parameter|system|shell|exec|command|cwd|envs|env_file|lookup_env|lookup_value|fetch_file|read_file)[\\s\\(\\:]+", value.value)
    not regex.match("(?i)\\$1\\$[a-zA-Z0-9]{1,8}\\$.{22}", value.value)
    value.value in common_default_passwords
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    value.ir_type == "Boolean"
    value.value == false
}

is_variable_or_reference(value) {
    walk(value, [_, v])
    v.ir_type == "VariableReference"
} else {
    walk(value, [_, v])
    v.ir_type == "FunctionCall"
    v.name in {"ref", "import", "get", "lookup", "secret", "parameter", "ssm", "kms", "vault", "secretsmanager", "aws", "gcp", "azure", "lookup_secret", "get_secret", "get_parameter", "lookup_parameter", "var", "env", "default", "require", "template", "include", "remote", "file", "lookup_file", "parse_yaml", "merge", "deep_merge", "from_file", "config", "config_file", "get_secret", "get_parameter", "lookup_secret", "lookup_parameter", "system", "shell", "exec", "command", "cwd", "envs", "env_file", "lookup_env", "lookup_value", "fetch_file", "read_file"}
} else {
    walk(value, [_, v])
    v.ir_type == "MethodCall"
    v.method in {"ref", "import", "get", "lookup", "secret", "parameter", "ssm", "kms", "vault", "secretsmanager", "lookup_secret", "get_secret", "get_parameter", "lookup_parameter", "var", "env", "default", "require", "template", "include", "remote", "file", "lookup_file", "parse_yaml", "merge", "deep_merge", "from_file", "config", "config_file", "get_secret", "get_parameter", "lookup_secret", "lookup_parameter", "system", "shell", "exec", "command", "cwd", "envs", "env_file", "lookup_env", "lookup_value", "fetch_file", "read_file"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_password_field(attr.name)
    is_hardcoded_value(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password or secret detected in infrastructure as code. Secrets should be managed externally using secure secret stores (e.g., AWS Secrets Manager, HashiCorp Vault). (CWE-259)"
    }
}