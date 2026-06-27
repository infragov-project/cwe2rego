package glitch

import data.glitch_lib

password_patterns := {"password", "passwd", "pwd", "secret", "token", "credential", "credentials", "api_key", "apikey", "sha512_password", "sha256_password", "md5_password", "key"}

has_password_pattern(name) {
    lower_name := lower(name)
    pattern := password_patterns[_]
    contains(lower_name, pattern)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not glitch_lib.has_variable_reference(value)
}

looks_like_file_path(str) {
    regex.match(`^(/|[a-zA-Z]:\\).*\.(keystore|truststore|jks|p12|pfx|pem|key|crt|cer|der)$`, str)
} else {
    regex.match(`^conf/\.(keystore|truststore)$`, str)
}

looks_like_class_name(str) {
    regex.match(`^([a-z][a-zA-Z0-9_]*\.)+[A-Z][a-zA-Z0-9_\.]*$`, str)
}

looks_like_boolean_string(str) {
    lower_str := lower(str)
    lower_str == "true"
    lower_str == "false"
}

is_likely_password_value(value) {
    is_hardcoded_string(value)
    not looks_like_file_path(value.value)
    not looks_like_class_name(value.value)
    not looks_like_boolean_string(value.value)
}

# Find all nested key-value pairs in Hash and Array structures
find_all_key_values(node) = key_values {
    key_values := {kv |
        walk(node, [_, item])
        item.ir_type == "Hash"
        entry := item.value[_]
        entry.key.ir_type == "String"
        kv := {"key": entry.key.value, "value": entry.value, "container": item}
    }
}

# Check direct Variable, Attribute, or KeyValue with password pattern
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    has_password_pattern(node.name)
    is_likely_password_value(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    has_password_pattern(node.name)
    is_likely_password_value(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}

# Check nested Hash entries with password pattern keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    # Find Hash nodes that contain key-value entries
    node.ir_type == "Hash"
    
    # Iterate through the Hash's entries
    entry := node.value[_]
    entry.key.ir_type == "String"
    key_name := entry.key.value
    
    has_password_pattern(key_name)
    is_likely_password_value(entry.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}

# Check Array elements that are Hashes for nested password fields
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Array"
    
    # Get array elements that are Hashes
    array_item := node.value[_]
    array_item.ir_type == "Hash"
    
    # Check entries within the Hash
    entry := array_item.value[_]
    entry.key.ir_type == "String"
    key_name := entry.key.value
    
    has_password_pattern(key_name)
    is_likely_password_value(entry.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}

# Check for KEY=VALUE format strings with password keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "String"
    str_val := node.value
    
    parts := regex.split("=", str_val)
    count(parts) >= 2
    
    left := trim_space(parts[0])
    right := trim_space(concat("=", array.slice(parts, 1, count(parts))))
    
    has_password_pattern(left)
    count(right) > 0
    
    # Filter out common false positives
    not lower(left) == "mysql_database"
    not lower(left) == "mysql_user"
    not lower(left) == "user"
    not lower(left) == "db"
    not lower(left) == "database"
    
    not looks_like_file_path(right)
    not looks_like_class_name(right)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. (CWE-259)"
    }
}