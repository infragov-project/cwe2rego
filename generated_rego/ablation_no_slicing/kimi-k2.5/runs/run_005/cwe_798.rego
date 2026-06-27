package glitch

import data.glitch_lib

credential_field_patterns := {"password", "passwd", "pwd", "secret", "secret_key", "access_key", "api_key", "token", "auth_token", "private_key", "certificate", "cert_file", "cert_path", "ca_file", "ca_path", "ssh_key", "root_password", "master_password", "bootstrap_password", "admin_password", "initial_password", "setup_password", "connection_string", "dsn", "uri", "database_url", "key", "key_data", "key_file", "key_path", "keystore", "truststore", "ca_cert", "public_key", "ciphertext", "webhook_secret", "client_secret", "oauth_client_secret", "vault_token", "sha512_password", "sha256_password", "password_hash", "user_password", "bind_password", "ldap_password", "keytab", "sensitive"}

insecure_default_values := {"password", "secret", "admin", "pass", "root", "123456", "changeme", "default", "guest", "test", "demo", "sample", "example", "qwerty", "letmein", "welcome", "monkey", "dragon", "baseball", "football", "superman", "batman", "trustno1"}

is_credential_field_name(key_name) {
    lower_key := lower(key_name)
    pattern := credential_field_patterns[_]
    contains(lower_key, pattern)
}

is_insecure_default(str) {
    lower_str := lower(str)
    default_val := insecure_default_values[_]
    lower_str == default_val
}

is_file_path(str) {
    startswith(str, "/")
} else {
    startswith(str, "C:\\")
} else {
    startswith(str, "c:\\")
} else {
    startswith(str, "\\\\")
} else {
    startswith(str, "./")
} else {
    startswith(str, "../")
}

is_external_reference(str) {
    startswith(str, "var.")
} else {
    startswith(str, "local.")
} else {
    startswith(str, "module.")
} else {
    startswith(str, "data.")
} else {
    contains(str, "${")
} else {
    contains(str, "{{")
} else {
    startswith(str, "fn::")
}

is_hardcoded_credential_value(val) {
    val.ir_type == "String"
    str := val.value
    count(str) > 0
    not str == "null"
    not str == "nil"
    not str == ""
    not is_external_reference(str)
    not is_file_path(str)
}

walk_hash_entries(node, prefix) = result {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    key_name := entry.key.value
    new_prefix := concat(".", [prefix, key_name]) if prefix != "" else key_name
    result := array.concat(
        [{{
            "key": key_name,
            "full_key": new_prefix,
            "value": entry.value,
            "line": entry.key.line,
            "column": entry.key.column
        }}],
        walk_hash_entries(entry.value, new_prefix)
    ) if entry.value.ir_type == "Hash" or entry.value.ir_type == "Array"
    else [{{
        "key": key_name,
        "full_key": new_prefix,
        "value": entry.value,
        "line": entry.key.line,
        "column": entry.key.column
    }}]
}

walk_hash_entries(node, prefix) = [] {
    not node.ir_type == "Hash"
}

walk_array_entries(node, prefix) = result {
    node.ir_type == "Array"
    elem := node.value[_]
    result := walk_hash_entries(elem, prefix)
}

walk_array_entries(node, prefix) = [] {
    not node.ir_type == "Array"
}

all_nested_entries(node, prefix) = result {
    node.ir_type == "Hash"
    result := walk_hash_entries(node, prefix)
}

all_nested_entries(node, prefix) = result {
    node.ir_type == "Array"
    result := walk_array_entries(node, prefix)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    var.value.ir_type == "Hash"
    
    entries := walk_hash_entries(var.value, var.name)
    entry := entries[_]
    
    is_credential_field_name(entry.key)
    is_hardcoded_credential_value(entry.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": {
            "ir_type": "KeyValue",
            "name": entry.full_key,
            "value": entry.value,
            "line": entry.value.line,
            "column": entry.value.column,
            "end_line": entry.value.end_line,
            "end_column": entry.value.end_column,
            "code": entry.value.code
        },
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coding credentials in source code. Use environment variables, secrets management systems, or encrypted storage. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    is_credential_field_name(var.name)
    is_hardcoded_credential_value(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coding credentials in source code. Use environment variables, secrets management systems, or encrypted storage. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    stmt := parent.statements[_]
    stmt.ir_type == "ConditionalStatement"
    
    inner_var := stmt.statements[_]
    inner_var.ir_type == "Variable"
    is_credential_field_name(inner_var.name)
    is_hardcoded_credential_value(inner_var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": inner_var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coding credentials in source code. Use environment variables, secrets management systems, or encrypted storage. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    stmt := parent.statements[_]
    stmt.ir_type == "ConditionalStatement"
    stmt.else_statement != null
    
    inner_var := stmt.else_statement.statements[_]
    inner_var.ir_type == "Variable"
    is_credential_field_name(inner_var.name)
    is_hardcoded_credential_value(inner_var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": inner_var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coding credentials in source code. Use environment variables, secrets management systems, or encrypted storage. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := parent.attributes[_]
    is_credential_field_name(attr.name)
    is_hardcoded_credential_value(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coding credentials in source code. Use environment variables, secrets management systems, or encrypted storage. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_credential_field_name(attr.name)
    is_hardcoded_credential_value(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coding credentials in source code. Use environment variables, secrets management systems, or encrypted storage. (CWE-798)"
    }
}