package glitch

import data.glitch_lib

credential_pattern := "(?i)(password|secret|key|token|credential|auth|access_key|secret_key|apikey|private_key|secret_value|passwd|pwd|secret_uuid|username|user)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(credential_pattern, node.name)
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in IaC script - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(credential_pattern, node.name)
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in IaC script - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_node := pair.key
    key_node.ir_type == "String"
    regex.match(credential_pattern, key_node.value)
    value_node := pair.value
    value_node.ir_type == "String"
    value_node.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": value_node,
        "path": parent.path,
        "description": "Hard-coded credential in IaC script - Avoid using hard-coded credentials. (CWE-798)"
    }
}