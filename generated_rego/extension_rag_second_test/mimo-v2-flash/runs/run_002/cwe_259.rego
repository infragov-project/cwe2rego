package glitch

import data.glitch_lib

sensitive_keywords := {"password", "passwd", "pwd", "pass", "secret_key", "api_key", "token", "client_secret", "access_key", "secret", "private_key", "passphrase", "key"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    name_key := node.name
    lower_name_key := lower(name_key)
    keyword := sensitive_keywords[_]
    contains(lower_name_key, keyword)
    value := node.value
    value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded password in variable '%s' (CWE-259)", [name_key])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    name_key := node.name
    lower_name_key := lower(name_key)
    keyword := sensitive_keywords[_]
    contains(lower_name_key, keyword)
    value := node.value
    value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded password in attribute '%s' (CWE-259)", [name_key])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.key
    node.value
    name_key := node.key
    lower_name_key := lower(name_key)
    keyword := sensitive_keywords[_]
    contains(lower_name_key, keyword)
    value := node.value
    value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded password in hash key '%s' (CWE-259)", [name_key])
    }
}