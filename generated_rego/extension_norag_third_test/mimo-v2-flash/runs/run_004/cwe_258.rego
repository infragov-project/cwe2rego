package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "passwd", "pwd", "secret", "token", "api_key", "credential", "auth", "key"}

is_password_key(name) {
    lower_name := lower(name)
    contains(lower_name, "password")
} else {
    lower_name := lower(name)
    contains(lower_name, "secret")
} else {
    lower_name := lower(name)
    contains(lower_name, "token")
} else {
    lower_name := lower(name)
    contains(lower_name, "credential")
} else {
    lower_name := lower(name)
    contains(lower_name, "auth")
}

is_empty_password_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
}

is_false_positive(name) {
    # Exclude non-credential fields that contain the word "password"
    # Common false positives based on CWE-258 examples
    patterns := {
        "password_reset", "password_policy", "password_expire",
        "password_age", "password_min", "password_max",
        "password_length", "password_history", "password_lock",
        "password_unlock", "password_reuse", "password_complexity"
    }
    lower_name := lower(name)
    pattern := patterns[_]
    contains(lower_name, pattern)
}

# 1. Direct Variables (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    not is_false_positive(v.name)
    is_password_key(v.name)
    is_empty_password_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields must not be set to empty values. (CWE-258)"
    }
}

# 2. Direct Attributes (Atomic Units)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    not is_false_positive(attr.name)
    is_password_key(attr.name)
    is_empty_password_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields must not be set to empty values. (CWE-258)"
    }
}

# 3. Hash Attributes in Ansible Variables (Nested Hash)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "Hash"
    
    walk(v.value, [path, n])
    n.ir_type == "String"
    n.value == ""
    
    key := find_hash_key(path, v.value)
    
    key != ""
    not is_false_positive(key)
    is_password_key(key)
    
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration file (nested) - Password fields must not be set to empty values. (CWE-258)"
    }
}

# 4. Hash Attributes in AtomicUnit Attributes (Nested Hash)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    
    walk(attr.value, [path, n])
    n.ir_type == "String"
    n.value == ""
    
    key := find_hash_key(path, attr.value)
    
    key != ""
    not is_false_positive(key)
    is_password_key(key)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file (nested) - Password fields must not be set to empty values. (CWE-258)"
    }
}

# Helper to find the key in a Hash path
find_hash_key(path, hash_val) = key {
    # Path structure: [index, "key", index, "key", ...]
    # We need the last string element in the path
    count(path) >= 2
    last_str_index := count(path) - 2
    key_part := path[last_str_index]
    is_string(key_part)
    key := key_part
} else {
    key := ""
}