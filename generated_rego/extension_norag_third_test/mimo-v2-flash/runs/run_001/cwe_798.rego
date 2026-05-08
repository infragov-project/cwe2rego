package glitch

import data.glitch_lib

sensitive_key_pattern := "(?i).*(password|secret|token|key|credential|auth|passphrase|access_key|secret_key|private_key|api_key|bearer_token).*"

is_sensitive_key(key_str) {
    regex.match(sensitive_key_pattern, key_str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    is_sensitive_key(node.name)
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Embedded secrets in IaC scripts pose a security risk (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_sensitive_key(node.name)
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Embedded secrets in IaC scripts pose a security risk (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, hash_node])
    hash_node.ir_type == "Hash"
    some i
    pair := hash_node.value[i]
    key_expr := pair.key
    value_expr := pair.value
    key_expr.ir_type == "String"
    is_sensitive_key(key_expr.value)
    value_expr.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": value_expr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Embedded secrets in IaC scripts pose a security risk (CWE-798)"
    }
}