package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "pwd", "pass", "secret", "auth_token", "api_key", "apikey", "credentials", "creds", "secret_key", "access_secret", "connection_string", "conn_str", "uri", "activationkey"}

is_password_field(name) {
    lower_name := lower(name)
    term := password_keywords[_]
    regex.match(sprintf(".*%s.*", [term]), lower_name)
}

is_empty_string(value) {
    value.ir_type == "String"
    count(trim_space(value.value)) == 0
}

is_null_value(value) {
    value.ir_type == "Null"
}

is_undef_value(value) {
    value.ir_type == "Undef"
}

is_empty_value(value) {
    is_empty_string(value)
}

is_empty_value(value) {
    is_null_value(value)
}

is_empty_value(value) {
    is_undef_value(value)
}

is_whitelist_field(name) {
    whitelist := {"proxy_password"}
    regex.match(sprintf("^.*%s$", [whitelist[_]]), name)
}

is_valid_config_context(parent) {
    parent.type != "function"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    is_password_field(node.name)
    not is_whitelist_field(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or secret fields should not be empty, null, or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    is_valid_config_context(parent)
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_password_field(attr.name)
    not is_whitelist_field(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or secret fields should not be empty, null, or contain only whitespace. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested_ub := parent.unit_blocks[_]
    is_valid_config_context(nested_ub)
    attrs := nested_ub.attributes
    attr := attrs[_]
    is_password_field(attr.name)
    not is_whitelist_field(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or secret fields should not be empty, null, or contain only whitespace. (CWE-258)"
    }
}