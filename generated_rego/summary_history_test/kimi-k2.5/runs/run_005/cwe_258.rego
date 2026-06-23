package glitch

import data.glitch_lib

password_patterns := {"password", "passwd", "pwd", "passw", "secret", "auth_token", "api_key", "private_key", "credentials", "credential", "login_secret", "root_password", "admin_password", "db_password", "database_password", "token", "auth", "activationkey", "activation_key"}

excluded_contexts_exact := {"cache", "caches", "proxy", "proxies", "tmp", "temp", "temporary", "backup", "backups", "log", "logs", "debug", "test", "testing", "example", "sample", "demo"}
excluded_suffixes := {"__api_token", "__cache_token", "__api_key"}

is_empty_string(value) {
    value.ir_type == "String"
    trim_space(value.value) == ""
}

is_null_or_undef(value) {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_explicit_empty(value) {
    is_empty_string(value)
} else {
    is_null_or_undef(value)
}

has_password_name(name) {
    lowercase := lower(name)
    not is_excluded_context(lowercase)
    contains_password_pattern(lowercase)
}

is_excluded_context(name) {
    pattern := excluded_contexts_exact[_]
    contains(name, pattern)
} else {
    suffix := excluded_suffixes[_]
    endswith(name, suffix)
}

contains_password_pattern(name) {
    pattern := password_patterns[_]
    contains(name, pattern)
}

value_is_empty_or_contains_empty_password(value) {
    is_explicit_empty(value)
} else {
    value.ir_type == "Hash"
    check_hash_empty(value)
} else {
    value.ir_type == "Array"
    check_array_elements(value)
}

check_hash_empty(hash) {
    some key
    hash.value[key]
    key.ir_type == "String"
    has_password_name(key.value)
    is_explicit_empty(hash.value[key])
}

check_array_elements(arr) {
    arr.value[_].ir_type == "Null"
} else {
    arr.value[_].ir_type == "Undef"
} else {
    arr.value[_].ir_type == "String"
    trim_space(arr.value[_].value) == ""
} else {
    elem := arr.value[_]
    elem.ir_type == "Hash"
    check_hash_empty(elem)
}

contains_empty_var_reference(value) {
    value.ir_type == "VariableReference"
    is_string(value.value)
}

check_function_call_empty_arg(func) {
    func.ir_type == "FunctionCall"
    arg := func.args[_]
    value_is_empty_or_contains_empty_password(arg)
} else {
    func.ir_type == "FunctionCall"
    arg := func.args[_]
    contains_empty_var_reference(arg)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    has_password_name(attr.name)
    value_is_empty_or_contains_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty, null, undefined, or contain empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_password_name(attr.name)
    value_is_empty_or_contains_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty, null, undefined, or contain empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    has_password_name(var.name)
    value_is_empty_or_contains_empty_password(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty, null, undefined, or contain empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_password_name(attr.name)
    check_function_call_empty_arg(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty, null, undefined, or contain empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    has_password_name(attr.name)
    check_function_call_empty_arg(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty, null, undefined, or contain empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    has_password_name(var.name)
    check_function_call_empty_arg(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password fields should not be empty, null, undefined, or contain empty strings. (CWE-258)"
    }
}