package glitch

import data.glitch_lib

password_exact := {"password", "pwd", "passwd", "secret", "credential", "auth_token", "api_key", "access_key", "secret_key"}

auth_suffixes := {"_password", "_pwd", "_passwd", "_key", "_token", "_secret"}

# Variable names that are known to be safe when empty (not actual passwords)
known_safe_empty := {
    "subscription_manager_activationkey",
    "gitlab_runner__api_token",
    "gitlab_runner__cache_access_key",
    "gitlab_runner__cache_secret_key"
}

is_password_field(name) {
    lower_name := lower(name)
    not known_safe_empty[lower_name]
    password_exact[lower_name]
} else {
    lower_name := lower(name)
    not known_safe_empty[lower_name]
    endswith(lower_name, auth_suffixes[_])
} else {
    lower_name := lower(name)
    not known_safe_empty[lower_name]
    regex.match(".*_password_.*", lower_name)
}

is_empty_value(value) {
    value.ir_type == "String"
    trim_space(value.value) == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

check_keyvalue(kv) {
    is_password_field(kv.name)
    is_empty_value(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_keyvalue(var)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    check_keyvalue(attr)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.name == "default"
    var.value.ir_type == "Array"
    arr := var.value.value[_]
    arr.ir_type == "Array"
    inner := arr.value[_]
    inner.ir_type == "KeyValue"
    inner.name == "password"
    is_empty_value(inner.value)
    result := {
        "type": "sec_empty_pass",
        "element": inner,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    vars := glitch_lib.all_variables(ub)
    var := vars[_]
    check_keyvalue(var)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    atomic_units := glitch_lib.all_atomic_units(ub)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    check_keyvalue(attr)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := parent.attributes[_]
    check_keyvalue(attrs)
    result := {
        "type": "sec_empty_pass",
        "element": attrs,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    check_keyvalue(node)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or contain only whitespace. (CWE-258)"
    }
}