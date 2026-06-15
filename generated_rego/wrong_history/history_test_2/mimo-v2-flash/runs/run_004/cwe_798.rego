package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "key", "token", "credential", "passwd", "pwd", "private_key", "public_key", "certificate", "pem", "key_material", "connection_string", "dsn", "uri"}

check_sensitive_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not regex.match("^[A-Za-z0-9+/=]+$", value.value)
} else {
    value.ir_type == "String"
    count(value.value) > 20
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name_lower := lower(attr.name)
    some kw in sensitive_keywords
    contains(attr.name_lower, kw)
    
    check_sensitive_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding sensitive credentials directly in code or configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name_lower := lower(attr.name)
    contains(attr.name_lower, "user_data")
    contains(attr.name_lower, "custom_data")
    
    check_sensitive_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in initialization scripts - Avoid embedding credentials in user data or custom data. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name_lower := lower(attr.name)
    contains(attr.name_lower, "file")
    contains(attr.name_lower, "content")
    
    check_sensitive_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials in file content - Avoid writing credentials to disk files. (CWE-798)"
    }
}