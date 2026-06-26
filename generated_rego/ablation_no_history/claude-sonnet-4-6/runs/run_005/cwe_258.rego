package glitch

import data.glitch_lib

password_field_pattern := "(?i).*(password|passwd|passphrase|pwd|secret|activation_key|activationkey|regkey|registration_key).*"

excluded_field_pattern := "(?i).*(proxy_pass|public_key|key_name|key_file|key_path|key_id|ssh_pub|authorized_key|known_hosts|sslclient|api_key|access_key|secret_key).*"

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

is_password_field(name) {
    regex.match(password_field_pattern, name)
    not regex.match(excluded_field_pattern, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    v := all_vars[_]
    is_password_field(v.name)
    is_empty_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields should not be assigned empty, null, or blank values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    is_password_field(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields should not be assigned empty, null, or blank values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)

    empty_attr := all_attrs[_]
    is_password_field(empty_attr.name)
    is_empty_value(empty_attr.value)

    attr := all_attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    arg.value == empty_attr.name

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields should not be assigned empty, null, or blank values. (CWE-258)"
    }
}