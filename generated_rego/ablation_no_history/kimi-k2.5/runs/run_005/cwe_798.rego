package glitch

import data.glitch_lib

default_pattern_strings := {
    "password", "secret", "token", "key", "cert", "credential", "auth",
    "passwd", "pwd", "api_key", "access_key", "private_key", "secret_key",
    "api_token", "auth_token", "certificate", "creds", "conn_string",
    "connection_string", "jdbc", "database_url", "account_key", "storage_key"
}

default_weak_values := {
    "password", "password123", "admin", "root", "test", "demo", "example",
    "changeme", "default", "123456", "secret", "token", "key", "temp",
    "temporary", "TODO", "FIXME", "HACK"
}

is_credential_name(name) {
    lower_name := lower(name)
    pattern := default_pattern_strings[_]
    contains(lower_name, pattern)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_secure_external_ref(value)
}

is_secure_external_ref(val) {
    val.ir_type == "FunctionCall"
    name := lower(val.name)
    secure_patterns := {"secret", "vault", "data", "lookup", "env", "var", "get_secret", "get_vault"}
    pattern := secure_patterns[_]
    contains(name, pattern)
} else {
    val.ir_type == "VariableReference"
    ref_name := lower(val.value)
    secure_prefixes := {"var.", "data.", "secret.", "vault.", "env."}
    prefix := secure_prefixes[_]
    startswith(ref_name, prefix)
}

is_credential_field(key_str) {
    is_credential_name(key_str)
}

get_string_value(node) = val {
    node.ir_type == "String"
    val := node.value
} else = val {
    node.ir_type == "VariableReference"
    val := node.value
} else = val {
    val := ""
}

has_hardcoded_credential_in_value(node, base_key) {
    [path, val] := walk(node)
    val.ir_type == "Hash"
    [_, kv] := walk(val.value)
    key_str := get_string_value(kv.key)
    full_key := concat(".", [base_key, key_str])
    is_credential_field(key_str)
    is_hardcoded_string(kv.value)
}

has_hardcoded_credential_in_value(node, base_key) {
    [path, val] := walk(node)
    val.ir_type == "Array"
    [_, item] := walk(val.value)
    has_hardcoded_credential_in_value(item, base_key)
}

get_credential_from_value(node, base_key) = {"key": full_key, "value": item_val, "element": item_val} {
    [_, val] := walk(node)
    val.ir_type == "Hash"
    [_, kv] := walk(val.value)
    key_str := get_string_value(kv.key)
    full_key := concat(".", [base_key, key_str])
    is_credential_field(key_str)
    is_hardcoded_string(kv.value)
    item_val := kv.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_credential_name(var.name)
    is_hardcoded_string(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding credentials in IaC scripts. Use secure secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    is_credential_name(attr.name)
    is_hardcoded_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding credentials in IaC scripts. Use secure secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    cred := get_credential_from_value(var.value, var.name)
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.element,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding credentials in IaC scripts. Use secure secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    cred := get_credential_from_value(attr.value, attr.name)
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.element,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding credentials in IaC scripts. Use secure secret management instead. (CWE-798)"
    }
}