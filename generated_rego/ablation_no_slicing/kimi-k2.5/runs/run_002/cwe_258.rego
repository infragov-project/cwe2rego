package glitch

import data.glitch_lib
import future.keywords.in

password_keywords := {"password", "passwd", "pwd", "pass", "secret", "admin_password", "root_password", "user_password", "credential_password", "db_password", "database_password", "api_key", "access_key", "tls_password", "ssl_password", "cert_password", "auth_secret", "client_secret", "session_secret", "encryption_key", "signing_key", "private_key", "secret_key", "api_token", "access_token", "refresh_token", "bearer_token"}

is_password_key(name) {
    lower_name := lower(name)
    some kw in password_keywords
    kw == lower_name
} else {
    lower_name := lower(name)
    some kw in password_keywords
    startswith(lower_name, concat("", [kw, "_"]))
} else {
    lower_name := lower(name)
    some kw in password_keywords
    endswith(lower_name, concat("", ["_", kw]))
} else {
    lower_name := lower(name)
    some kw in password_keywords
    contains(lower_name, concat("", ["_", kw, "_"]))
} else {
    lower_name := lower(name)
    some kw in password_keywords
    endswith(lower_name, kw)
} else {
    lower_name := lower(name)
    some kw in password_keywords
    startswith(lower_name, kw)
}

is_excluded_key(name) {
    lower_name := lower(name)
    some pattern in {"_username", "_user", "_hash", "_id", "_type", "_method", "_path", "_file", "_dir", "_url", "_host", "_port", "_server", "_cert_ca", "_cert_mode", "_protocol", "_proxy_user"}
    contains(lower_name, pattern)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

has_empty_password_in_value(value, vars) {
    value.ir_type == "Hash"
    some entry in value.value
    is_password_key(entry.name)
    not is_excluded_key(entry.name)
    is_empty_value(entry.value)
}

has_empty_password_in_value(value, vars) {
    value.ir_type == "Hash"
    some entry in value.value
    has_empty_password_in_value(entry.value, vars)
}

has_empty_password_in_value(value, vars) {
    value.ir_type == "Array"
    some item in value.value
    has_empty_password_in_value(item, vars)
}

has_empty_password_in_value(value, vars) {
    value.ir_type == "FunctionCall"
    some arg in value.args
    arg.ir_type == "VariableReference"
    some v in vars
    v.name == arg.value
    is_password_key(v.name)
    not is_excluded_key(v.name)
    is_empty_value(v.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {v | some v in glitch_lib.all_variables(parent)}
    var := vars[_]
    is_password_key(var.name)
    not is_excluded_key(var.name)
    is_empty_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_key(attr.name)
    not is_excluded_key(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    some entry in attr.value.value
    is_password_key(entry.name)
    not is_excluded_key(entry.name)
    is_empty_value(entry.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    vars := {v | some v in glitch_lib.all_variables(parent)}
    attr.value.ir_type == "FunctionCall"
    some arg in attr.value.args
    arg.ir_type == "VariableReference"
    some v in vars
    v.name == arg.value
    is_password_key(v.name)
    not is_excluded_key(v.name)
    is_empty_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_password_key(node.name)
    not is_excluded_key(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Hash"
    some entry in node.value.value
    is_password_key(entry.name)
    not is_excluded_key(entry.name)
    is_empty_value(entry.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_password_key(node.name)
    not is_excluded_key(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration - Password or secret fields should not be empty or null. (CWE-258)"
    }
}