package glitch

import data.glitch_lib

sensitive_keys := {"protocol", "url", "source", "endpoint", "uri", "location", "enable_https", "https_only", "secure_transfer", "ssl_mode", "require_ssl"}

disabled_attr_names := {"ssl_mode", "secure_transfer", "https_only", "enable_https", "require_ssl", "validate_certs"}
disabled_values := {"disabled", "false", "disable_ssl", "no"}

contains_unencrypted_pattern(value) {
    glitch_lib.traverse(value, "(?i)\\bhttp\\b")
} else {
    glitch_lib.traverse(value, "(?i)http://")
} else {
    value.ir_type == "String"
    regex.match("(?i).*http://.*", value.value)
}

is_disabled_encryption(value) {
    value.ir_type == "String"
    disabled_values[value.value]
} else {
    value.ir_type == "Boolean"
    value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    sensitive_keys[attr.name]
    contains_unencrypted_pattern(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted configuration detected. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    disabled_attr_names[attr.name]
    is_disabled_encryption(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_entries := var.value.value
    entry := hash_entries[_]
    entry.key.ir_type == "String"
    sensitive_keys[lower(entry.key.value)]
    contains_unencrypted_pattern(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted configuration in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type != "Hash"
    contains_unencrypted_pattern(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted URL in variable. (CWE-319)"
    }
}