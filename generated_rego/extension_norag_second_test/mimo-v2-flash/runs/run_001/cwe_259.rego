package glitch

import data.glitch_lib

credential_keywords := {"password", "secret", "token", "credential", "auth_key", "passphrase", "api_key", "access_token", "secret_key", "passwd", "key", "password_digest", "sha512_password", "bcrypt_password"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    count({k | k = credential_keywords[_]; glitch_lib.contains(var.name, k)}) > 0
    var.value.ir_type == "String"
    not glitch_lib.traverse_var(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password in variable (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    count({k | k = credential_keywords[_]; glitch_lib.contains(attr.name, k)}) > 0
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in attribute (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    value.ir_type == "String"
    count({k | k = credential_keywords[_]; glitch_lib.contains(key.value, k)}) > 0
    not glitch_lib.traverse_var(value)
    result := {
        "type": "sec_hard_pass",
        "element": value,
        "path": parent.path,
        "description": "Hard-coded password in hash key-value pair (CWE-259)"
    }
}