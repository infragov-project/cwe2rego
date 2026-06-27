package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "token", "credential", "creds", "auth", "private_key", "privatekey", "ssh_key", "cert", "certificate", "api_key", "apikey", "access_key", "secret_key", "encryption_key", "secret_access_key", "master_password", "admin_password", "root_password", "default_password", "truststore_password", "keystore_password"}

is_credential_name(name) {
    lower_name := lower(name)
    kw := credential_keywords[_]
    contains(lower_name, kw)
}

is_safe_value_type(val) {
    val.ir_type in {"BlockExpr", "Null", "Undef", "Boolean", "Integer", "Float"}
}

is_reference(val) {
    val.ir_type in {"VariableReference", "FunctionCall", "MethodCall"}
}

has_reference_in_complex(val) {
    walk(val, [_, v])
    is_reference(v)
}

is_plausible_secret(val) {
    val.ir_type == "String"
    val.value != ""
    count(val.value) >= 4
    not regex.match("(?i)^password$|^pass$|^secret$|^pwd$|^test$|^example$|^demo$|^sample$|^changeme$|^change[_-]me$|^placeholder$|^todo$|^fixme$|^xxx$|^insert$|^here$|^null$|^none$|^nil$|^true$|^false$|^user$|^username$|^name$|^admin$|^root$|^default$|^yes$|^no$|^on$|^off$", val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])

    node.ir_type in {"Variable", "Attribute"}

    is_credential_name(node.name)

    not is_safe_value_type(node.value)
    not is_reference(node.value)

    node.value.ir_type == "String"
    is_plausible_secret(node.value)

    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be embedded directly in infrastructure definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])

    node.ir_type in {"Variable", "Attribute"}

    is_credential_name(node.name)

    not is_safe_value_type(node.value)
    not is_reference(node.value)

    node.value.ir_type in {"Array", "Hash"}
    not has_reference_in_complex(node.value)

    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be embedded directly in infrastructure definitions. (CWE-798)"
    }
}