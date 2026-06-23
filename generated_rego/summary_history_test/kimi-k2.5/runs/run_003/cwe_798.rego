package glitch

import data.glitch_lib

credential_field_patterns := {
    "password", "passwd", "pwd", "secret_word", "passphrase",
    "username", "user", "uid", "login", "account",
    "credential", "creds", "auth_token", "auth_key",
    "api_key", "api_secret", "api_token", "client_id", "client_secret",
    "access_key", "access_token", "secret_key", "private_key",
    "ssh_key", "tls_key", "ssl_key",
    "certificate", "cert", "ca_cert", "root_ca",
    "key_pair", "key_file", "key_material",
    "encryption_key", "decryption_key", "shared_secret",
    "master_key", "kek", "dek",
    "salt", "seed", "iv", "initialization_vector",
    "connection_string", "conn_string", "dsn",
    "database_url", "db_url", "mongodb_uri", "redis_url",
    "default_password", "initial_password", "bootstrap_password",
    "admin_password", "root_password", "system_password",
    "sha512_password", "md5_password", "sha256_password",
    "keystore_password", "truststore_password",
    "key"
}

ldap_schema_suffixes := {"_dn", "_attribute", "_objectclass", "_tree_dn"}

is_ldap_schema_field(name) {
    suffix := ldap_schema_suffixes[_]
    endswith(lower(name), suffix)
}

is_ldap_dn(value) {
    regex.match("^(uid|cn|ou|dc)=[^,]+(,(uid|cn|ou|dc)=[^,]+)+$", value)
}

is_placeholder(value) {
    regex.match("^[<{\\[]?[A-Z_]+[>}\\]$]|^[<{\\[]?vault[>}\\]$]|^[<{\\[]?secret[_-]?ref[>}\\]$]|^[<{\\[]?ref[>}\\]$]|^[<{\\[]?data\\.[a-zA-Z_.]+[>}\\]$]|^\\$\\{", value)
}

is_path_like(value) {
    regex.match("^(/[a-zA-Z0-9_.\\-]+)+\\.?[a-zA-Z0-9]*$|^([a-zA-Z]:[\\\\/])?([a-zA-Z0-9_.\\-]+[\\\\/])+[a-zA-Z0-9_.\\-]*$", value)
}

is_standard_admin(value) {
    admin_names := {"root", "admin", "administrator", "operator"}
    lower(value) == admin_names[_]
}

is_uuid(value) {
    regex.match("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", value)
}

is_base64_like(value) {
    regex.match("^[A-Za-z0-9+/]{40,}={0,2}$", value)
}

is_high_entropy(value) {
    regex.match("^[A-Za-z0-9]{32,}$", value)
}

matches_field_pattern(lower_name, pattern) {
    lower_name == pattern
}

matches_field_pattern(lower_name, pattern) {
    endswith(lower_name, concat("", ["_", pattern]))
}

matches_field_pattern(lower_name, pattern) {
    startswith(lower_name, concat("", [pattern, "_"]))
}

matches_field_pattern(lower_name, pattern) {
    contains(lower_name, concat("", [".", pattern, "."]))
}

matches_field_pattern(lower_name, pattern) {
    contains(lower_name, concat("", [".", pattern]))
}

matches_field_pattern(lower_name, pattern) {
    contains(lower_name, concat("", ["_", pattern, "_"]))
}

matches_field_pattern(lower_name, pattern) {
    contains(lower_name, concat("", ["['", pattern, "']"]))
}

matches_field_pattern(lower_name, pattern) {
    regex.match(concat("", ["(^|\\.|_|-|\\[')", pattern, "($|\\.|_|-|\\'])"]), lower_name)
}

is_credential_name(name) {
    lower_name := lower(name)
    pattern := credential_field_patterns[_]
    matches_field_pattern(lower_name, pattern)
}

is_credential_value(value) {
    is_hardcoded_string(value)
    not is_uuid(value.value)
}

is_hardcoded_string(node) {
    node.ir_type == "String"
    node.value != null
    node.value != ""
    not is_placeholder(node.value)
    not is_ldap_dn(node.value)
}

has_variable_reference(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
}

has_secure_function_call(node) {
    walk(node, [_, n])
    n.ir_type == "FunctionCall"
    regex.match("^(vault_|data\\.|var\\.|aws_|azurerm_|google_|module\\.)", n.name)
}

is_secure_reference(node) {
    has_variable_reference(node)
}

is_secure_reference(node) {
    has_secure_function_call(node)
}

is_sensitive_field(name, value) {
    is_credential_name(name)
    not is_standard_admin(value)
    not is_ldap_dn(value)
    not is_path_like(value)
}

extract_credential_from_name(full_name) = cred_name {
    contains(full_name, "['")
    parts := regex.find_all_string_submatch_n(".*\\['([^']+)'\\]$", full_name, 1)
    count(parts) > 0
    count(parts[0]) > 1
    cred_name := parts[0][1]
}

extract_credential_from_name(full_name) = cred_name {
    contains(full_name, ".")
    parts := split(full_name, ".")
    count(parts) > 0
    cred_name := parts[count(parts)-1]
}

extract_credential_from_name(full_name) = cred_name {
    not contains(full_name, "['")
    not contains(full_name, ".")
    cred_name := full_name
}

check_hash_entry_for_credential(entry, parent_path, result) {
    entry.key.ir_type == "String"
    key_name := entry.key.value
    is_sensitive_field(key_name, entry.value.value)
    is_credential_value(entry.value)
    not is_secure_reference(entry.value)
    not is_ldap_schema_field(key_name)
    
    result := {
        "type": "sec_hard_secr",
        "element": {"key": entry.key, "value": entry.value},
        "path": parent_path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in source code. (CWE-798)"
    }
}

check_variable_for_credential(var, parent_path, result) {
    var.value.ir_type == "String"
    extracted := extract_credential_from_name(var.name)
    is_sensitive_field(extracted, var.value.value)
    is_credential_value(var.value)
    not is_secure_reference(var.value)
    not is_ldap_schema_field(extracted)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent_path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in source code. (CWE-798)"
    }
}

walk_hash_for_credentials(hash_node, parent_path, found_result) {
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    check_hash_entry_for_credential(entry, parent_path, found_result)
}

walk_hash_for_credentials(hash_node, parent_path, found_result) {
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    nested := entry.value
    nested.ir_type == "Hash"
    walk_hash_for_credentials(nested, parent_path, found_result)
}

walk_hash_for_credentials(hash_node, parent_path, found_result) {
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    nested := entry.value
    nested.ir_type == "Array"
    arr_elem := nested.value[_]
    arr_elem.ir_type == "Hash"
    walk_hash_for_credentials(arr_elem, parent_path, found_result)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    walk_hash_for_credentials(node, parent.path, result)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_variable_for_credential(var, parent.path, result)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    extracted := extract_credential_from_name(attr.name)
    is_sensitive_field(extracted, attr.value.value)
    is_credential_value(attr.value)
    not is_secure_reference(attr.value)
    not is_ldap_schema_field(extracted)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in source code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "String"
    extracted := extract_credential_from_name(attr.name)
    is_sensitive_field(extracted, attr.value.value)
    is_credential_value(attr.value)
    not is_secure_reference(attr.value)
    not is_ldap_schema_field(extracted)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in source code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "UnitBlock"
    node.path != ""
    
    nested_attr := node.attributes[_]
    nested_attr.value.ir_type == "String"
    extracted := extract_credential_from_name(nested_attr.name)
    is_sensitive_field(extracted, nested_attr.value.value)
    is_credential_value(nested_attr.value)
    not is_secure_reference(nested_attr.value)
    not is_ldap_schema_field(extracted)
    
    result := {
        "type": "sec_hard_secr",
        "element": nested_attr,
        "path": node.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in source code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "UnitBlock"
    node.path != ""
    
    nested_var := node.variables[_]
    check_variable_for_credential(nested_var, node.path, result)
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "UnitBlock"
    node.path != ""
    
    cond_stmt := node.statements[_]
    cond_stmt.ir_type == "ConditionalStatement"
    
    walk(cond_stmt, [_, stmt_node])
    stmt_node.ir_type == "Variable"
    check_variable_for_credential(stmt_node, node.path, result)
}