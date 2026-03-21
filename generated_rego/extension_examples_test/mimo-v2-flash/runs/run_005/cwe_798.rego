package glitch

import data.glitch_lib
import future.keywords.in

sensitive_patterns = {
    "password", "secret", "api_key", "apikey", "token", "access_key", "accesskey",
    "secret_key", "secretkey", "admin_password", "master_password", "client_secret",
    "private_key", "credential", "auth", "pwd", "passwd", "secret_id", "key", "user"
}

script_attributes = {
    "startup_script", "bootstrap_commands", "user_data", "init_script", "config_file",
    "script", "command", "inline_script", "bootstrap_script"
}

matches_sensitive(str) = true {
    some pattern in sensitive_patterns
    regex.match(sprintf("(?i).*%s.*", [pattern]), str)
}

is_static_value(v) {
    v.ir_type in {"String", "Integer", "Float", "Boolean", "Complex"}
    not glitch_lib.has_variable_reference(v)
} else {
    v.ir_type == "Array"
    every elem in v.value {
        is_static_value(elem)
    }
} else {
    v.ir_type == "Hash"
    every key, value in v.value {
        is_static_value(key)
        is_static_value(value)
    }
}

find_sensitive_in_value(value) {
    value.ir_type == "Hash"
    pair := value.value[_]
    matches_sensitive(pair.key.value)
    is_static_value(pair.value)
}

find_sensitive_in_value(value) {
    value.ir_type == "Hash"
    pair := value.value[_]
    find_sensitive_in_value(pair.value)
}

find_sensitive_in_value(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    find_sensitive_in_value(elem)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    matches_sensitive(var.name)
    is_static_value(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Variable contains static value in sensitive field. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    find_sensitive_in_value(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Variable contains static value in sensitive field. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    matches_sensitive(attr.name)
    is_static_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in attribute - Attribute contains static value in sensitive field. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    find_sensitive_in_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in attribute - Attribute contains static value in sensitive field. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    attr.name in script_attributes
    attr.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in inline script - The script may contain embedded secrets. (CWE-798)"
    }
}