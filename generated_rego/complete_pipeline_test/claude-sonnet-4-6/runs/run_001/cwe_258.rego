package glitch

import data.glitch_lib

is_password_name(name) {
    regex.match("(?i).*(password|passwd|pwd|passphrase|pre_shared_key|client_secret|token_secret|signing_secret|activationkey|activation_key|bind_pass|auth_pass|db_pass|admin_pass|root_pass|master_pass|user_pass|initial_pass|default_pass|vpn_pass|key_passphrase|keystore_pass|truststore_pass).*", name)
    not regex.match("(?i).*(proxy_pass|proxy_pwd|proxy_password).*", name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

is_empty_value(value) {
    value.ir_type == "Null"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_password_name(variable.name)
    is_empty_value(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    ref_attrs := glitch_lib.all_attributes(parent)
    ref_attr := ref_attrs[_]
    ref_attr.name == arg.value
    is_empty_value(ref_attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.name == arg.value
    is_empty_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credential fields should not be assigned empty values. (CWE-258)"
    }
}