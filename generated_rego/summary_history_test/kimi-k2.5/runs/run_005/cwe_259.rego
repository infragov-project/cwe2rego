package glitch

import data.glitch_lib

credential_keywords := {
    "password", "passwd", "pwd", "secret", "secret_key", "api_key", "token",
    "auth_token", "access_key", "credential", "login_password", "root_password",
    "admin_password", "database_password", "db_password", "sha512_password",
    "pre_shared_key", "keystore_password", "truststore_password"
}

default_passwords := {
    "password", "admin", "123456", "12345678", "qwerty", "default", "changeme",
    "secret", "password123", "admin123", "test", "test123", "guest", "root",
    "toor", "letmein", "welcome", "passwort", "pass", "login", "user", "cassandra"
}

is_credential_field(name) {
    lower_name := lower(name)
    keyword_match(lower_name)
}

is_credential_field(name) {
    lower_name := lower(name)
    suffix_match(lower_name)
}

is_credential_field(name) {
    parts := split(name, ".")
    part := parts[_]
    lower_part := lower(part)
    keyword_match(lower_part)
}

is_credential_field(name) {
    parts := split(name, ".")
    part := parts[_]
    lower_part := lower(part)
    suffix_match(lower_part)
}

is_credential_field(name) {
    parts := split(name, "[")
    part := parts[_]
    clean_part := replace(part, "]", "")
    clean_part2 := replace(clean_part, "'", "")
    clean_part3 := replace(clean_part2, "\"", "")
    lower_part := lower(clean_part3)
    keyword_match(lower_part)
}

is_credential_field(name) {
    parts := split(name, "[")
    part := parts[_]
    clean_part := replace(part, "]", "")
    clean_part2 := replace(clean_part, "'", "")
    clean_part3 := replace(clean_part2, "\"", "")
    lower_part := lower(clean_part3)
    suffix_match(lower_part)
}

keyword_match(name) {
    name == credential_keywords[_]
}

suffix_match(name) {
    endswith(name, "_password")
}

suffix_match(name) {
    endswith(name, "_secret")
}

suffix_match(name) {
    endswith(name, "_key")
    not contains(name, "monkey")
    not contains(name, "keystone")
    not contains(name, "keypair")
}

suffix_match(name) {
    endswith(name, "_token")
    not contains(name, "count")
    not contains(name, "tokenize")
    not contains(name, "num_tokens")
    not contains(name, "max_tokens")
}

suffix_match(name) {
    endswith(name, "_auth")
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_variable_reference_only(value.value)
}

is_variable_reference_only(str) {
    regex.match("^\\$\\{[^}]+\\}$", str)
}

is_variable_reference_only(str) {
    regex.match("^\\$[A-Za-z_][A-Za-z0-9_]*$", str)
}

is_suspicious_default(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    lower_value == default_passwords[_]
}

is_connection_string_with_creds(name, value) {
    lower_name := lower(name)
    contains_connection_pattern(lower_name)
    value.ir_type == "String"
    regex.match("(?i)(://[^/]*:[^@]*@|password=|pwd=|pass=)", value.value)
}

contains_connection_pattern(str) {
    regex.match("connection[_-]?string", str)
}

contains_connection_pattern(str) {
    regex.match("conn[_-]?string", str)
}

contains_connection_pattern(str) {
    regex.match("^dsn$", str)
}

contains_connection_pattern(str) {
    regex.match("^uri$", str)
}

contains_connection_pattern(str) {
    regex.match("^url$", str)
}

contains_connection_pattern(str) {
    regex.match("^endpoint$", str)
}

is_env_var_with_credential(str) {
    parts := split(str, "=")
    count(parts) > 1
    key := parts[0]
    is_credential_field(key)
}

has_env_var_credential(value) {
    value.ir_type == "String"
    is_env_var_with_credential(value.value)
}

is_vault_or_secret_manager(value) {
    value.ir_type == "String"
    regex.match("(?i)(vault|secrets?_manager|secretsmanager|key_vault|secret_manager|terraform\\.io|data\\.aws_|data\\.azurerm_|lookup\\()", value.value)
}

is_data_source_or_var_ref(value) {
    value.ir_type == "VariableReference"
}

is_data_source_or_var_ref(value) {
    value.ir_type == "FunctionCall"
}

is_data_source_or_var_ref(value) {
    value.ir_type == "Access"
}

is_data_source_or_var_ref(value) {
    value.ir_type == "MethodCall"
}

is_data_source_or_var_ref(value) {
    value.ir_type == "Hash"
    count(value.value) == 0
}

is_likely_not_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "token_count")
}

is_likely_not_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "num_tokens")
}

is_likely_not_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "max_tokens")
}

is_likely_not_password_field(name) {
    lower_name := lower(name)
    regex.match("^\\d+$", name)
}

is_hash_or_array(node) {
    node.ir_type == "Hash"
}

is_hash_or_array(node) {
    node.ir_type == "Array"
}

walk_for_credentials(node) = results {
    results := {found |
        [_, walked_node] := walk(node)
        walked_node.ir_type == "Hash"
        entry := walked_node.value[_]
        entry.key.ir_type == "String"
        k := entry.key.value
        is_credential_field(k)
        not is_likely_not_password_field(k)
        entry.value.ir_type == "String"
        val := entry.value
        count(val.value) > 0
        not is_variable_reference_only(val.value)
        not is_vault_or_secret_manager(val)
        not is_data_source_or_var_ref(val)
        found := {
            "key": k,
            "value": val,
            "element": entry
        }
    }
}

walk_for_defaults(node) = results {
    results := {found |
        [_, walked_node] := walk(node)
        walked_node.ir_type == "Hash"
        entry := walked_node.value[_]
        entry.key.ir_type == "String"
        k := entry.key.value
        is_credential_field(k)
        not is_likely_not_password_field(k)
        entry.value.ir_type == "String"
        val := entry.value
        lower_val := lower(val.value)
        lower_val == default_passwords[_]
        found := {
            "key": k,
            "value": val,
            "element": entry
        }
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    var_name := var.name
    is_credential_field(var_name)
    not is_likely_not_password_field(var_name)
    var.value.ir_type == "String"
    is_hardcoded_string(var.value)
    not is_vault_or_secret_manager(var.value)
    not is_data_source_or_var_ref(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password in variable - Avoid using hard-coded passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    is_credential_field(var.name)
    not is_likely_not_password_field(var.name)
    is_suspicious_default(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded default password in variable - Avoid using weak or default hard-coded passwords. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    var.value.ir_type == "Hash"
    found := walk_for_credentials(var.value)
    count(found) > 0
    item := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Use of hard-coded password in nested variable structure - Avoid using hard-coded passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    var.value.ir_type == "Array"
    arr_elem := var.value.value[_]
    is_hash_or_array(arr_elem)
    found := walk_for_credentials(arr_elem)
    count(found) > 0
    item := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Use of hard-coded password in nested variable array - Avoid using hard-coded passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    var.value.ir_type == "Hash"
    found := walk_for_defaults(var.value)
    count(found) > 0
    item := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Use of hard-coded default password in nested variable - Avoid using weak or default hard-coded passwords. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_credential_field(attr.name)
    not is_likely_not_password_field(attr.name)
    is_hardcoded_string(attr.value)
    not is_vault_or_secret_manager(attr.value)
    not is_data_source_or_var_ref(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    found := walk_for_credentials(attr.value)
    count(found) > 0
    item := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Use of hard-coded password in nested attribute - Avoid using hard-coded passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    arr_elem := attr.value.value[_]
    is_hash_or_array(arr_elem)
    found := walk_for_credentials(arr_elem)
    count(found) > 0
    item := found[_]
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Use of hard-coded password in nested attribute array - Avoid using hard-coded passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_credential_field(attr.name)
    not is_likely_not_password_field(attr.name)
    is_suspicious_default(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded default password - Avoid using weak or default hard-coded passwords. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_connection_string_with_creds(attr.name, attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in connection string - Avoid embedding credentials in connection strings. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    arr_elem := attr.value.value[_]
    arr_elem.ir_type == "String"
    has_env_var_credential(arr_elem)
    result := {
        "type": "sec_hard_pass",
        "element": arr_elem,
        "path": parent.path,
        "description": "Use of hard-coded password in environment variable - Avoid embedding credentials in environment variables. Use secret management systems instead. (CWE-259)"
    }
}