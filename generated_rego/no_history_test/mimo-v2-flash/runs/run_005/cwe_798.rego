package glitch

import data.glitch_lib

hash_key_pattern := "(?i)(password|secret|api[_-]?key|token|access[_-]?key|secret[_-]?key|credential|auth|pass|private[_-]?key|connection[_-]?string|admin[_-]?password|root[_-]?password)"

# Rule for variables with nested hash values containing credential keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [path, node])
    node.ir_type == "KeyValue"
    node.key.ir_type == "String"
    key_str := node.key.value
    regex.match(hash_key_pattern, key_str)
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential found - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

# Rule for attributes with nested hash values containing credential keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [path, node])
    node.ir_type == "KeyValue"
    node.key.ir_type == "String"
    key_str := node.key.value
    regex.match(hash_key_pattern, key_str)
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential found - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

# Rule for variables with names matching credential pattern and string values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(hash_key_pattern, var.name)
    var.value.ir_type == "String"
    var.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential found - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

# Rule for attributes with names matching credential pattern and string values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(hash_key_pattern, attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential found - Avoid using hard-coded credentials in IaC scripts. (CWE-798)"
    }
}