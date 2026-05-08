package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "pwd", "secret", "token", "api_key", "credential", "auth_key", "key"}

is_password_keyword(name) {
    kw := password_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b", [kw]), name)
}

is_hardcoded_string(node) {
    node.ir_type == "String"
}

is_hardcoded_value(node) {
    is_hardcoded_string(node)
} else {
    node.ir_type == "Integer"
} else {
    node.ir_type == "Boolean"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    is_password_keyword(node.name)
    is_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password found in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_password_keyword(node.name)
    is_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password found in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_password_keyword(pair.key.value)
    is_hardcoded_value(pair.value)
    result := {
        "type": "sec_hard_pass",
        "element": pair.value,
        "path": parent.path,
        "description": "Hard-coded password found in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}