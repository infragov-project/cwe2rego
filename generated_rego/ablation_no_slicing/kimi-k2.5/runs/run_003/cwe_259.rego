package glitch

import data.glitch_lib

password_fields := {"password", "passwd", "pwd", "secret", "admin_password", "root_password", "user_password", "db_password", "database_password", "master_password", "primary_password", "initial_password", "default_password", "sha512_password", "no_password", "credentials", "login", "auth", "authentication", "access_key", "secret_key", "api_key", "api_secret", "private_key", "certificate_password", "keystore_password", "truststore_password", "key", "mysql_password", "postgres_password", "db_pass"}

common_weak_passwords := {"password", "admin", "123456", "root", "changeme", "password123", "admin123", "default", "test", "guest", "null", "none", "empty", "secret", "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "telarista", "passw0rd", "some_password"}

is_sensitive_field(name) {
    password_fields[lower(name)]
}

is_sensitive_field(name) {
    lower_names := {"password", "passwd", "pwd", "secret", "key"}
    endswith(lower(name), lower_names[_])
}

is_sensitive_field(name) {
    lower_names := {"password_", "passwd_", "secret_", "key_"}
    startswith(lower(name), lower_names[_])
}

contains_password_pattern(value) {
    parts := split(value, "=")
    count(parts) >= 2
    key_part := parts[0]
    is_sensitive_field(key_part)
}

extract_password_value(value) = result {
    parts := split(value, "=")
    count(parts) >= 2
    result := concat("=", array.slice(parts, 1, count(parts)))
}

is_hardcoded_value(value) {
    value.ir_type == "String"
    value.value != ""
}

is_weak_password_value(value) {
    value.ir_type == "String"
    common_weak_passwords[lower(value.value)]
}

should_detect_password(key_name, value) {
    is_sensitive_field(key_name)
    is_hardcoded_value(value)
}

check_hash_kv(key, value, root_path) = result {
    should_detect_password(key.value, value)
    not is_weak_password_value(value)
    result := {
        "type": "sec_hard_pass",
        "element": {
            "ir_type": "KeyValue",
            "key": key,
            "value": value,
            "line": key.line,
            "column": key.column,
            "end_line": value.end_line,
            "end_column": value.end_column,
            "code": key.code
        },
        "path": root_path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

check_hash_kv(key, value, root_path) = result {
    should_detect_password(key.value, value)
    is_weak_password_value(value)
    result := {
        "type": "sec_hard_pass",
        "element": {
            "ir_type": "KeyValue",
            "key": key,
            "value": value,
            "line": key.line,
            "column": key.column,
            "end_line": value.end_line,
            "end_column": value.end_column,
            "code": key.code
        },
        "path": root_path,
        "description": "Use of Weak Hard-coded Password - Avoid using common or weak hard-coded passwords. Use strong, externally managed secrets instead. (CWE-259)"
    }
}

check_string_env_password(str_elem, root_path) = result {
    str_elem.ir_type == "String"
    value := str_elem.value
    contains_password_pattern(value)
    pass_val := extract_password_value(value)
    not common_weak_passwords[lower(pass_val)]
    result := {
        "type": "sec_hard_pass",
        "element": str_elem,
        "path": root_path,
        "description": "Use of Hard-coded Password - Password pattern found in string value. Avoid hard-coding passwords in environment variables or configuration files. (CWE-259)"
    }
}

check_string_env_password(str_elem, root_path) = result {
    str_elem.ir_type == "String"
    value := str_elem.value
    contains_password_pattern(value)
    pass_val := extract_password_value(value)
    common_weak_passwords[lower(pass_val)]
    result := {
        "type": "sec_hard_pass",
        "element": str_elem,
        "path": root_path,
        "description": "Use of Weak Hard-coded Password - Weak password pattern found in string value. Avoid using common or weak passwords. (CWE-259)"
    }
}

check_kv_pair(kv, root_path) = result {
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    result := check_hash_kv(kv.key, kv.value, root_path)
}

check_kv_pair(kv, root_path) = result {
    kv.key.ir_type == "String"
    is_sensitive_field(kv.key.value)
    kv.value.ir_type == "Hash"
    some i
    inner_kv := kv.value.value[i]
    result := check_kv_pair(inner_kv, root_path)
}

check_kv_pair(kv, root_path) = result {
    kv.key.ir_type == "String"
    is_sensitive_field(kv.key.value)
    kv.value.ir_type == "Array"
    some i
    arr_elem := kv.value.value[i]
    arr_elem.ir_type == "Hash"
    some j
    inner_kv := arr_elem.value[j]
    result := check_kv_pair(inner_kv, root_path)
}

check_kv_pair(kv, root_path) = result {
    kv.key.ir_type == "String"
    kv.value.ir_type == "Array"
    some i
    arr_elem := kv.value.value[i]
    arr_elem.ir_type == "String"
    result := check_string_env_password(arr_elem, root_path)
}

walk_from_value(value, root_path) = result {
    value.ir_type == "Hash"
    some i
    kv := value.value[i]
    result := check_kv_pair(kv, root_path)
}

walk_from_value(value, root_path) = result {
    value.ir_type == "Array"
    some i
    elem := value.value[i]
    elem.ir_type == "Hash"
    some j
    kv := elem.value[j]
    result := check_kv_pair(kv, root_path)
}

walk_from_value(value, root_path) = result {
    value.ir_type == "Array"
    some i
    elem := value.value[i]
    elem.ir_type == "String"
    result := check_string_env_password(elem, root_path)
}

get_path(node) = path {
    node.path
    path := node.path
} else = "" {
    true
}

find_all_unit_blocks[block] {
    walk(input, [_, node])
    node.ir_type == "UnitBlock"
    block := node
}

find_all_unit_blocks[block] {
    input.ir_type == "UnitBlock"
    block := input
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, node])
    node.ir_type == "Variable"
    node.name
    is_sensitive_field(node.name)
    node.value.ir_type == "String"
    is_hardcoded_value(node.value)
    
    not is_weak_password_value(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords in variable definitions. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, node])
    node.ir_type == "Variable"
    node.name
    is_sensitive_field(node.name)
    node.value.ir_type == "String"
    is_weak_password_value(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": path,
        "description": "Use of Weak Hard-coded Password - Avoid using common or weak hard-coded passwords. Use strong, externally managed secrets instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, node])
    node.ir_type == "Variable"
    node.value
    var_result := walk_from_value(node.value, path)
    result := var_result
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, au])
    au.ir_type == "AtomicUnit"
    
    walk(au, [_, attr])
    attr.ir_type == "Attribute"
    attr.name
    is_sensitive_field(attr.name)
    
    attr.value.ir_type == "String"
    is_hardcoded_value(attr.value)
    not is_weak_password_value(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords in resource attributes. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, au])
    au.ir_type == "AtomicUnit"
    
    walk(au, [_, attr])
    attr.ir_type == "Attribute"
    attr.name
    is_sensitive_field(attr.name)
    
    attr.value.ir_type == "String"
    is_weak_password_value(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": path,
        "description": "Use of Weak Hard-coded Password - Avoid using common or weak hard-coded passwords. Use strong, externally managed secrets instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, au])
    au.ir_type == "AtomicUnit"
    
    walk(au, [_, attr])
    attr.ir_type == "Attribute"
    attr.value
    
    attr_result := walk_from_value(attr.value, path)
    result := attr_result
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, node])
    node.ir_type == "Hash"
    some i
    kv := node.value[i]
    result := check_kv_pair(kv, path)
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, node])
    node.ir_type == "Attribute"
    node.name
    is_sensitive_field(node.name)
    
    node.value.ir_type == "String"
    is_hardcoded_value(node.value)
    not is_weak_password_value(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords in configuration attributes. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    block := find_all_unit_blocks[_]
    path := get_path(block)
    
    walk(block, [_, node])
    node.ir_type == "Attribute"
    node.name
    is_sensitive_field(node.name)
    
    node.value.ir_type == "String"
    is_weak_password_value(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": path,
        "description": "Use of Weak Hard-coded Password - Avoid using common or weak hard-coded passwords. Use strong, externally managed secrets instead. (CWE-259)"
    }
}