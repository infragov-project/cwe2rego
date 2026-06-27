package glitch

import data.glitch_lib

password_field_patterns := {"password", "passwd", "pwd", "secret", "admin_password", "root_password", "master_password", "default_password", "user_password", "db_password", "database_password", "credential", "credentials", "auth_token", "api_key", "api_secret", "private_key", "secret_key", "access_key_secret", "sha512_password", "sha256_password", "truststore_password", "keystore_password"}

key_field_names := {"key"}

is_password_field(name) {
    field_lower := lower(name)
    pattern := password_field_patterns[_]
    contains(field_lower, pattern)
}

is_key_field_only(name) {
    field_lower := lower(name)
    k := key_field_names[_]
    field_lower == k
}

looks_like_base64(str) {
    regex.match("^[A-Za-z0-9+/]{8,}={0,2}$", str)
}

looks_like_base64_alt(str) {
    regex.match("^[A-Za-z0-9_-]{20,}$", str)
}

is_keystore_path(str) {
    str == "conf/.keystore"
} else {
    str == "conf/.truststore"
} else {
    endswith(str, ".keystore")
} else {
    endswith(str, ".truststore")
} else {
    contains(lower(str), "/.keystore")
} else {
    contains(lower(str), "/.truststore")
}

is_suspicious_key_value(value) {
    value.ir_type == "String"
    not is_keystore_path(value.value)
    not glitch_lib.has_variable_reference(value)
}

contains_env_credential(str) {
    env_patterns := {"PASSWORD=", "SECRET=", "API_KEY=", "API_SECRET=", "PRIVATE_KEY=", "TOKEN="}
    pattern := env_patterns[_]
    contains(upper(str), pattern)
}

make_password_result(parent_path, key_name, val, msg) = result {
    result = {
        "type": "sec_hard_pass",
        "element": {
            "ir_type": "Attribute",
            "name": key_name,
            "value": val,
            "line": val.line,
            "column": val.column,
            "end_line": val.end_line,
            "end_column": val.end_column,
            "code": val.code
        },
        "path": parent_path,
        "description": sprintf("%s (CWE-259)", [msg])
    }
}

# Detect password fields in any Hash node - use walk to find all nested hashes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_name := entry.key.value
    val := entry.value
    
    is_password_field(key_name)
    val.ir_type == "String"
    val.value != ""
    not glitch_lib.has_variable_reference(val)
    
    result = make_password_result(parent.path, key_name, val, "Use of Hard-coded Password - Passwords should not be hard-coded in configuration files. Use secure external secret management instead.")
}

# Detect Base64 encoded passwords
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_name := entry.key.value
    val := entry.value
    
    is_password_field(key_name)
    val.ir_type == "String"
    looks_like_base64(val.value)
    
    result = make_password_result(parent.path, key_name, val, "Potentially hard-coded password in Base64 encoding - Base64-encoded credentials detected. Use secure external secret management instead.")
}

# Detect Base64 alternative (URL-safe) encoded passwords
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_name := entry.key.value
    val := entry.value
    
    is_password_field(key_name)
    val.ir_type == "String"
    looks_like_base64_alt(val.value)
    
    result = make_password_result(parent.path, key_name, val, "Potentially hard-coded password in Base64 encoding - Base64-encoded credentials detected. Use secure external secret management instead.")
}

# Detect key fields with suspicious values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_name := entry.key.value
    val := entry.value
    
    is_key_field_only(key_name)
    is_suspicious_key_value(val)
    
    result = make_password_result(parent.path, key_name, val, "Use of Hard-coded Key - Keys should not be hard-coded in configuration files. Use secure external secret management instead.")
}

# Variables at top level with password fields
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_field(var.name)
    var.value.ir_type == "String"
    var.value.value != ""
    not glitch_lib.has_variable_reference(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords should not be hard-coded in variable definitions. Use secure external secret management instead. (CWE-259)"
    }
}

# Attributes in atomic units with password fields
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    not glitch_lib.has_variable_reference(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Passwords should not be hard-coded in configuration files. Use secure external secret management instead. (CWE-259)"
    }
}

# Environment variable style credentials in arrays
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "String"
    contains_env_credential(elem.value)
    not glitch_lib.has_variable_reference(elem)
    parts := split(elem.value, "=")
    key_part := parts[0]
    is_password_field(lower(key_part))
    count(parts) > 1
    value_part := parts[1]
    value_part != ""
    value_part != "null"
    value_part != "nil"
    value_part != "undefined"
    result := {
        "type": "sec_hard_pass",
        "element": elem,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Password found in environment variable format. Use secure external secret management instead. (CWE-259)"
    }
}

# Hashes inside Arrays - password fields
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Hash"
    entry := elem.value[_]
    key_name := entry.key.value
    val := entry.value
    
    is_password_field(key_name)
    val.ir_type == "String"
    val.value != ""
    not glitch_lib.has_variable_reference(val)
    
    result = make_password_result(parent.path, key_name, val, "Use of Hard-coded Password - Passwords should not be hard-coded in configuration files. Use secure external secret management instead.")
}

# Hashes inside Arrays - key fields
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Hash"
    entry := elem.value[_]
    key_name := entry.key.value
    val := entry.value
    
    is_key_field_only(key_name)
    is_suspicious_key_value(val)
    
    result = make_password_result(parent.path, key_name, val, "Use of Hard-coded Key - Keys should not be hard-coded in configuration files. Use secure external secret management instead.")
}