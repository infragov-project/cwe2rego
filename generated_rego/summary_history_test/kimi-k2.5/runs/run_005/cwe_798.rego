package glitch

import data.glitch_lib

credential_names := {"password", "passwd", "pwd", "secretpassword", "secret_password", "api_key", "apikey", "api_secret", "apisecret", "token", "access_token", "auth_token", "secret_token", "secret", "client_secret", "private_key", "secret_key", "encryption_key", "connection_string", "dsn", "credentials"}

credential_suffixes := {"_password", "_passwd", "_pwd", "_secret", "_key", "_token", "_apikey", "_keystore", "_truststore"}

common_username_values := {"admin", "administrator", "root", "user", "guest", "test", "demo"}

auth_context_patterns := {"auth", "login", "credential", "access", "token"}

is_file_path(str) {
    regex.match("^[./~]", str)
}

is_file_path(str) {
    regex.match("^[a-zA-Z]:", str)
}

is_file_path(str) {
    regex.match("/[a-zA-Z0-9_.-]+/", str)
}

is_placeholder_or_reference(str) {
    regex.match(".*\\$\\{.*\\}.*", str)
}

is_placeholder_or_reference(str) {
    regex.match("^(vault|var|local|data|module|env|secret|lookup|template|each|path|terraform|ref)\\..*", lower(str))
}

is_placeholder_or_reference(str) {
    regex.match("^\\s*\\$\\(", str)
}

is_placeholder_or_reference(str) {
    regex.match("^\\$[a-zA-Z_]", str)
}

is_placeholder_or_reference(str) {
    regex.match("^<<", str)
}

matches_credential_name(name) {
    lower_name := lower(name)
    cred := credential_names[_]
    lower_name == cred
}

matches_credential_name(name) {
    lower_name := lower(name)
    suffix := credential_suffixes[_]
    endswith(lower_name, suffix)
}

is_key_in_auth_context(key_name, hash_keys) {
    lower(key_name) == "key"
    key_auth := hash_keys[_]
    auth_ctx := auth_context_patterns[_]
    contains(lower(key_auth), auth_ctx)
}

extract_bracket_field_name(name) = extracted {
    regex.match("^[^']*\\['([^']+)'\\]", name)
    parts := regex.find_all_string_submatch_n("^[^']*\\['([^']+)'\\]", name, -1)
    count(parts) > 0
    count(parts[0]) > 1
    extracted := parts[0][1]
} else = name {
    true
}

is_likely_username_value(value) {
    lower_val := lower(value)
    common_username_values[lower_val]
}

check_string_value_credential(val, key_name, path) = result {
    val.ir_type == "String"
    val.value != ""
    not is_file_path(val.value)
    not is_placeholder_or_reference(val.value)
    not is_likely_username_value(val.value)
    
    matches_credential_name(key_name)
    
    result := {
        "type": "sec_hard_secr",
        "element": val,
        "path": path,
        "description": "Use of hard-coded credentials - Avoid embedding plaintext credentials in configurations. Use secure secret management instead. (CWE-798)"
    }
}

check_hash_main(hash_node, path, hash_keys) = result {
    entry_main := hash_node.value[_]
    key_name := entry_main.key.value
    
    check_result := check_string_value_credential(entry_main.value, key_name, path)
    check_result != null
    
    result := check_result
}

check_hash_auth(hash_node, path, hash_keys) = result {
    entry_auth := hash_node.value[_]
    key_name := entry_auth.key.value
    
    is_key_in_auth_context(key_name, hash_keys)
    
    val := entry_auth.value
    val.ir_type == "String"
    val.value != ""
    not is_file_path(val.value)
    not is_placeholder_or_reference(val.value)
    not is_likely_username_value(val.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": val,
        "path": path,
        "description": "Use of hard-coded credentials - Avoid embedding plaintext credentials in configurations. Use secure secret management instead. (CWE-798)"
    }
}

check_hash_credential(hash_node, path) = result {
    hash_node.ir_type == "Hash"
    
    hash_keys := [hk.key.value | hk := hash_node.value[_]]
    
    result := check_hash_main(hash_node, path, hash_keys)
}

check_hash_credential(hash_node, path) = result {
    hash_node.ir_type == "Hash"
    
    hash_keys := [hk2.key.value | hk2 := hash_node.value[_]]
    
    result := check_hash_auth(hash_node, path, hash_keys)
}

walk_check_hash(root, path) = result {
    walk(root, [_, node])
    
    node.ir_type == "Hash"
    
    result := check_hash_credential(node, path)
}

walk_check_array_hash(root, path) = result {
    walk(root, [_, node])
    
    node.ir_type == "Array"
    
    item_arr := node.value[_]
    result := check_hash_credential(item_arr, path)
}

walk_check_array_nested(root, path) = result {
    walk(root, [_, node])
    
    node.ir_type == "Array"
    
    item_arr2 := node.value[_]
    item_arr2.ir_type == "Hash"
    
    entry_arr := item_arr2.value[_]
    key_name := entry_arr.key.value
    
    result := check_string_value_credential(entry_arr.value, key_name, path)
}

check_var_credential(var, path) = result {
    var.ir_type == "Variable"
    var.value.ir_type == "String"
    var.value.value != ""
    not is_file_path(var.value.value)
    not is_placeholder_or_reference(var.value.value)
    not is_likely_username_value(var.value.value)
    
    candidate_names := {
        lower(var.name),
        lower(extract_bracket_field_name(var.name))
    }
    
    raw_parts := split(var.name, ".")
    raw_part := raw_parts[_]
    field_part_var := extract_bracket_field_name(raw_part)
    
    lower_field := lower(field_part_var)
    
    matches_credential_name(lower_field)
    
    result := {
        "type": "sec_hard_secr",
        "element": var.value,
        "path": path,
        "description": "Use of hard-coded credentials - Avoid embedding plaintext credentials in configurations. Use secure secret management instead. (CWE-798)"
    }
}

check_var_credential_alt(var, path) = result {
    var.ir_type == "Variable"
    var.value.ir_type == "String"
    var.value.value != ""
    not is_file_path(var.value.value)
    not is_placeholder_or_reference(var.value.value)
    not is_likely_username_value(var.value.value)
    
    raw_parts2 := split(var.name, ".")
    raw_part2 := raw_parts2[_]
    field_part_var2 := extract_bracket_field_name(raw_part2)
    
    lower_field2 := lower(field_part_var2)
    
    matches_credential_name(lower_field2)
    
    result := {
        "type": "sec_hard_secr",
        "element": var.value,
        "path": path,
        "description": "Use of hard-coded credentials - Avoid embedding plaintext credentials in configurations. Use secure secret management instead. (CWE-798)"
    }
}

get_all_variables(node) = vars {
    vars := {v |
        walk(node, [_, v])
        v.ir_type == "Variable"
    }
}

get_all_attributes(node) = attrs {
    attrs := {a |
        walk(node, [_, a])
        a.ir_type == "Attribute"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    result := check_var_credential(var, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    result := walk_check_hash(var.value, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    result := walk_check_array_hash(var.value, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    result := walk_check_array_nested(var.value, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    au := parent.atomic_units[_]
    attr := au.attributes[_]
    attr.value.ir_type == "String"
    attr.value.value != ""
    not is_file_path(attr.value.value)
    not is_placeholder_or_reference(attr.value.value)
    not is_likely_username_value(attr.value.value)
    
    matches_credential_name(attr.name)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding plaintext credentials in configurations. Use secure secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nested_ub := parent.unit_blocks[_]
    
    var := nested_ub.variables[_]
    result := check_var_credential_alt(var, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nested_ub := parent.unit_blocks[_]
    
    var := nested_ub.variables[_]
    result := walk_check_hash(var.value, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nested_ub := parent.unit_blocks[_]
    
    attr := nested_ub.attributes[_]
    attr.value.ir_type == "String"
    attr.value.value != ""
    not is_file_path(attr.value.value)
    not is_placeholder_or_reference(attr.value.value)
    not is_likely_username_value(attr.value.value)
    
    matches_credential_name(attr.name)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding plaintext credentials in configurations. Use secure secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    cond_stmt := parent.statements[_]
    cond_stmt.ir_type == "ConditionalStatement"
    
    stmt_var := get_all_variables(cond_stmt)[_]
    result := check_var_credential_alt(stmt_var, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    cond_stmt := parent.statements[_]
    cond_stmt.ir_type == "ConditionalStatement"
    
    stmt_var := get_all_variables(cond_stmt)[_]
    result := walk_check_hash(stmt_var.value, parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    result := check_hash_credential(node, parent.path)
}