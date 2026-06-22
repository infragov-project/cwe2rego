package glitch

import data.glitch_lib

credential_patterns := [
    "password", "secret", "_password", "__password", "_secret", "__secret",
    "private_key", "public_key", "ca_cert", "tls_key", "ssh_key",
    "api_key", "api_secret", "client_secret", "access_key", "access_token",
    "session_token", "connection_string", "root_password", "admin_password",
    "master_password", "replication_password", "keystore_password", "truststore_password",
    "broker_password", "cert_file", "key_file", "cert", "key", "token",
    "credentials", "creds", "passphrase", "pin", "auth_token", "api_token",
    "service_token", "access.secret", "access.key", "secret.key", "signing.key"
]

excluded_value_patterns := [
    "authenticator", "authorizer", "authentication", "authorization",
    "cacertfile", "ca_cert_file", "cert_file", "tls_cacertfile"
]

is_credential_field(name) {
    lower_name := lower(name)
    pattern := credential_patterns[_]
    contains(lower_name, pattern)
}

is_excluded_value_field(name) {
    lower_name := lower(name)
    pattern := excluded_value_patterns[_]
    contains(lower_name, pattern)
}

is_secure_reference(str) {
    regex.match("^\\$\\{", str)
}

is_secure_reference(str) {
    regex.match("^\\$[A-Za-z_]", str)
}

is_secure_reference(str) {
    regex.match("(?i)(var|local|data|module|secret|vault|kms|ssm|keyvault|lookup|vars)", str)
}

is_secure_reference(str) {
    regex.match("^\\{\\s*\\{", str)
}

is_java_class(str) {
    regex.match("^[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*)+$", str)
}

is_file_path(str) {
    regex.match("^(/[a-zA-Z0-9_\\-\\.]+)+/?$|^([a-zA-Z]:\\\\)?([a-zA-Z0-9_\\-\\.]+\\\\)+[a-zA-Z0-9_\\-\\.]+$", str)
}

is_hardcoded_value(str) {
    not is_secure_reference(str)
    not is_java_class(str)
    not is_file_path(str)
    count(str) > 0
}

check_hash_for_credentials(node, base_path, orig_path) = [result] {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    key_str := entry.key.value
    is_credential_field(key_str)
    not is_excluded_value_field(key_str)
    entry.value.ir_type == "String"
    val_str := entry.value.value
    is_hardcoded_value(val_str)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": orig_path,
        "description": sprintf("Use of Hard-coded Credentials - Sensitive credential field '%s' should not contain hardcoded values. Use external secret stores or variable references. (CWE-798)", [key_str])
    }
}

check_hash_for_credentials(node, base_path, orig_path) = [result] {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    _ := entry.key.value
    entry.value.ir_type == "Hash"
    result := check_hash_for_credentials(entry.value, [base_path, entry.key.value], orig_path)
}

check_hash_for_credentials(node, base_path, orig_path) = [result] {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    _ := entry.key.value
    entry.value.ir_type == "Array"
    item := entry.value.value[_]
    result := check_hash_for_credentials(item, [base_path, entry.key.value], orig_path)
}

get_chef_variable_name_parts(name) = parts {
    parts := split(name, "\\.")
}

get_chef_variable_name_parts(name) = parts {
    not contains(name, ".")
    startswith(name, "default[")
    inner := substring(name, 7, -1)
    clean := regex.replace(inner, "^\\['|'\\]$", "")
    parts := concat(".", split(clean, "']['"))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    val_str := var.value.value
    is_hardcoded_value(val_str)
    
    name_lower := lower(var.name)
    
    check1 {
        is_credential_field(var.name)
        not is_excluded_value_field(var.name)
    }
    check2 {
        parts := get_chef_variable_name_parts(var.name)
        part := parts[_]
        is_credential_field(part)
        not is_excluded_value_field(part)
    }
    
    result := {
        "type": "sec_hard_secr",
        "element": var.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Sensitive credential field '%s' should not contain hardcoded values. Use external secret stores or variable references. (CWE-798)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    result := check_hash_for_credentials(node, [], parent.path)[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atoms := glitch_lib.all_atomic_units(parent)
    atom := atoms[_]
    
    walk(atom, [path, node])
    node.ir_type == "Hash"
    
    result := check_hash_for_credentials(node, [], parent.path)[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atoms := glitch_lib.all_atomic_units(parent)
    atom := atoms[_]
    attrs := glitch_lib.all_attributes(atom)
    attr := attrs[_]
    
    is_credential_field(attr.name)
    not is_excluded_value_field(attr.name)
    
    attr.value.ir_type == "String"
    val_str := attr.value.value
    
    is_hardcoded_value(val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Sensitive credential field '%s' should not contain hardcoded values. Use external secret stores or variable references. (CWE-798)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := {n |
        walk(parent, [_, n])
        n.ir_type == "ConditionalStatement"
    }
    cond := conds[_]
    
    statements := cond.statements
    stmt := statements[_]
    
    walk(stmt, [path, node])
    node.ir_type == "Hash"
    
    result := check_hash_for_credentials(node, [], parent.path)[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := {n |
        walk(parent, [_, n])
        n.ir_type == "ConditionalStatement"
    }
    cond := conds[_]
    
    statements := cond.statements
    stmt := statements[_]
    stmt.ir_type == "Variable"
    
    stmt.value.ir_type == "String"
    val_str := stmt.value.value
    is_hardcoded_value(val_str)
    
    name_lower := lower(stmt.name)
    
    is_credential_field(stmt.name)
    not is_excluded_value_field(stmt.name)
    
    result := {
        "type": "sec_hard_secr",
        "element": stmt.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Sensitive credential field '%s' should not contain hardcoded values. Use external secret stores or variable references. (CWE-798)", [stmt.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := {n |
        walk(parent, [_, n])
        n.ir_type == "ConditionalStatement"
    }
    cond := conds[_]
    
    statements := cond.statements
    stmt := statements[_]
    stmt.ir_type == "Variable"
    
    stmt.value.ir_type == "String"
    val_str := stmt.value.value
    is_hardcoded_value(val_str)
    
    parts := get_chef_variable_name_parts(stmt.name)
    part := parts[_]
    is_credential_field(part)
    not is_excluded_value_field(part)
    
    result := {
        "type": "sec_hard_secr",
        "element": stmt.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Sensitive credential field '%s' should not contain hardcoded values. Use external secret stores or variable references. (CWE-798)", [stmt.name])
    }
}