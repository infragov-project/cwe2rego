package glitch

import data.glitch_lib

is_password_name(name) {
    regex.match(`(?i)(password|passwd|pwd|passphrase|credential|connection_string|dsn)`, name)
}

is_secret_name(name) {
    regex.match(`(?i)(secret|auth_token)`, name)
}

is_key_name(name) {
    regex.match(`(?i)(key$|_key_|^key_)`, name)
}

is_credential_name(name) {
    is_password_name(name)
} else {
    is_secret_name(name)
} else {
    is_key_name(name)
}

is_empty_value(val) {
    val.ir_type == "String"
    val.value == ""
} else {
    val.ir_type == "Undef"
} else {
    val.ir_type == "Null"
}

is_ansible_defaults(path) {
    regex.match(`(?i)defaults[-_/]main\.(yml|yaml)$`, path)
}

has_empty_credential_param(code) {
    regex.match(`(?i)\$[\w]*(?:password|passwd|pwd|secret|key|token|credential|passphrase|auth)[\w]*\s*=\s*(?:''|""|\bundef\b)`, code)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    not is_ansible_defaults(parent.path)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_credential_name(var.name)
    is_empty_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords and credentials should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    not is_ansible_defaults(parent.path)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_name(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords and credentials should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    not is_ansible_defaults(parent.path)
    walk(parent, [_, node])
    node.ir_type == "UnitBlock"
    has_empty_credential_param(node.code)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords and credentials should not be empty. (CWE-258)"
    }
}