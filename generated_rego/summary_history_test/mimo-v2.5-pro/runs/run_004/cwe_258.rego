package glitch

import data.glitch_lib

credential_keywords := {
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "secret_key", "private_key", "passphrase", "credential", "auth_token",
    "access_key", "activationkey", "ssh_password", "encryption_key"
}

credential_pattern := `password|passwd|pwd|secret|token|apikey|api_key|secret_key|private_key|passphrase|credential|auth_token|access_key|activationkey|ssh_password|encryption_key`

empty_cred_code_pattern := sprintf(`(?i)\$\w*(?:%s)\w*\s*=\s*(?:''|""|\bundef\b)`, [credential_pattern])

is_empty_or_null_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

name_has_credential_keyword(name) {
    lower_name := lower(name)
    keyword := credential_keywords[_]
    glitch_lib.contains(lower_name, keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node := parent.variables[_]
    name_has_credential_keyword(node.name)
    is_empty_or_null_value(node.value)

    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_credential_keyword(attr.name)
    is_empty_or_null_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty strings. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "UnitBlock"
    node.type == "definition"
    node.code != ""
    regex.match(empty_cred_code_pattern, node.code)

    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty strings. (CWE-258)"
    }
}