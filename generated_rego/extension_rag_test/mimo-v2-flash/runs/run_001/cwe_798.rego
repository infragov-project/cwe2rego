package glitch

import data.glitch_lib

sensitive_attributes := {"password", "secret", "token", "key", "credential", "auth", "private_key", "api_key", "secret_key", "db_password", "admin_password", "encryption_key", "connection_string", "db_pass", "db_credentials", "api_token", "ssh_private_key", "certificate", "access_key", "refresh_token", "client_secret", "secret_id", "sha512_password", "sha256_password", "md5_password", "db_user", "db_db", "db_host", "db_port"}

default_credentials := {"admin", "password", "root", "123456", "default", "test", "guest", "user", "password1", "password123", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "access", "login", "passw0rd", "password!", "changeme", "12345678", "123456789", "1234567890", "admin123", "administrator", "root123", "rootpassword", "password123", "telarista", "RedHat1!", "Administrator"}

base64_pattern := `^[A-Za-z0-9+/]*={0,2}$`

hashed_password_pattern := `^\$[0-9]\$`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_lower := lower(attr.name)
    keyword := sensitive_attributes[_]
    contains(name_lower, keyword)
    attr.value.ir_type == "String"
    value := attr.value.value
    value != ""
    result := {"type": "sec_hard_secr", "element": attr, "path": parent.path, "description": sprintf("Hard-coded credential in attribute: %s", [attr.name])}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    name_lower := lower(var.name)
    keyword := sensitive_attributes[_]
    contains(name_lower, keyword)
    var.value.ir_type == "String"
    value := var.value.value
    value != ""
    result := {"type": "sec_hard_secr", "element": var, "path": parent.path, "description": sprintf("Hard-coded credential in variable: %s", [var.name])}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    value := attr.value.value
    value != ""
    regex.match(base64_pattern, value)
    result := {"type": "sec_hard_secr", "element": attr, "path": parent.path, "description": sprintf("Base64-encoded credential in attribute: %s", [attr.name])}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    value := var.value.value
    value != ""
    regex.match(base64_pattern, value)
    result := {"type": "sec_hard_secr", "element": var, "path": parent.path, "description": sprintf("Base64-encoded credential in variable: %s", [var.name])}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    value := attr.value.value
    value != ""
    regex.match(hashed_password_pattern, value)
    result := {"type": "sec_hard_secr", "element": attr, "path": parent.path, "description": sprintf("Hashed password in attribute: %s", [attr.name])}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    value := var.value.value
    value != ""
    regex.match(hashed_password_pattern, value)
    result := {"type": "sec_hard_secr", "element": var, "path": parent.path, "description": sprintf("Hashed password in variable: %s", [var.name])}
}