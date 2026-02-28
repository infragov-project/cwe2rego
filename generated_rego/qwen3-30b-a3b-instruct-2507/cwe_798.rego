package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "password" or attr.name == "passwd" or attr.name == "pwd" or
    attr.name == "api_key" or attr.name == "apikey" or attr.name == "access_key" or
    attr.name == "secret_key" or attr.name == "token" or attr.name == "auth_token" or
    attr.name == "bearer_token" or attr.name == "ssh_key" or attr.name == "private_key" or
    attr.name == "pem" or attr.name == "encryption_key" or attr.name == "aes_key" or
    attr.name == "symmetric_key" or attr.name == "db_password" or attr.name == "mysql_password" or
    attr.name == "postgres_password" or attr.name == "database_password" or attr.name == "ldap_password" or
    attr.name == "sftp_password" or attr.name == "smtp_password" or attr.name == "client_secret" or
    attr.name == "client_id" or attr.name == "service_account_key"

    attr.value.ir_type == "String"
    not is_empty_or_whitespace(attr.value.value)
    not is_common_weak_password(attr.value.value)

    result := {
        "type": "sec_hard_user",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential detected. Credentials should never be embedded directly in IaC scripts. (CWE-798, CWE-259, CWE-321, CWE-1317)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "config"
    attr.value.ir_type == "Hash"
    nested_attr := attr.value.value[_]
    nested_attr.name == "password" or nested_attr.name == "passwd" or nested_attr.name == "pwd" or
    nested_attr.name == "api_key" or nested_attr.name == "apikey" or nested_attr.name == "access_key" or
    nested_attr.name == "secret_key" or nested_attr.name == "token" or nested_attr.name == "auth_token" or
    nested_attr.name == "bearer_token" or nested_attr.name == "ssh_key" or nested_attr.name == "private_key" or
    nested_attr.name == "pem" or nested_attr.name == "encryption_key" or nested_attr.name == "aes_key" or
    nested_attr.name == "symmetric_key" or nested_attr.name == "db_password" or nested_attr.name == "mysql_password" or
    nested_attr.name == "postgres_password" or nested_attr.name == "database_password" or nested_attr.name == "ldap_password" or
    nested_attr.name == "sftp_password" or nested_attr.name == "smtp_password" or nested_attr.name == "client_secret" or
    nested_attr.name == "client_id" or nested_attr.name == "service_account_key"

    nested_attr.value.ir_type == "String"
    not is_empty_or_whitespace(nested_attr.value.value)
    not is_common_weak_password(nested_attr.value.value)

    result := {
        "type": "sec_hard_user",
        "element": nested_attr,
        "path": parent.path,
        "description": "Hard-coded credential detected inside a config map. Credentials should be injected securely. (CWE-798, CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "access_key" or attr.name == "secret_key")
    attr.value.ir_type == "String"
    (attr.value.value == "AKIA" or attr.value.value == "s3")
    not is_safe_access_key(attr.value.value)

    result := {
        "type": "sec_hard_user",
        "element": attr,
        "path": parent.path,
        "description": "Possible hardcoded AWS credentials detected. Use secure secret management. (CWE-798, CWE-321)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "private_key"
    attr.value.ir_type == "String"
    (startswith(attr.value.value, "-----BEGIN RSA PRIVATE KEY-----") or
     startswith(attr.value.value, "-----BEGIN PRIVATE KEY-----") or
     startswith(attr.value.value, "-----BEGIN DSA PRIVATE KEY-----"))

    result := {
        "type": "sec_hard_user",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded private key detected. Private keys must not be embedded in IaC. (CWE-798, CWE-321)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "secret"
    attr.value.ir_type == "String"
    len(attr.value.value) >= 8
    regex.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$", attr.value.value)
    not has_secret_placeholder(attr.value.value)

    result := {
        "type": "sec_hard_user",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded secret detected with strong format. Secrets should be dynamically injected. (CWE-798)"
    }
}

is_empty_or_whitespace(s) {
    not regex.match("(?:\\S)", s)
}

is_common_weak_password(pw) {
    pw == "password"
    or pw == "123456"
    or pw == "admin"
    or pw == "root"
    or pw == "changeme"
    or pw == "letmein"
    or pw == "secret"
    or pw == "pass123"
    or pw == "qwerty"
    or pw == "abc123"
    or pw == "password1"
}

is_safe_access_key(access_key) {
    access_key == "AKIA" or access_key == "AKIA123"
    or regex.match("^[A-Z0-9]{16}$", access_key)
    or regex.match("^(AKIA|ASIA|CAIA|DAIA|GAIA|IAIA|MAIA|QAIA|SAIA)[A-Z0-9]{16}$", access_key)
}

has_secret_placeholder(s) {
    regex.match("{{.*}}|\\$\\{.*\\}|\\$\\$\\{.*\\}", s)
}