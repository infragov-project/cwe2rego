package glitch

import data.glitch_lib

sensitive_keywords := {"password", "pass", "passwd", "passphrase", "secret", "key", "api_key", "api_token", "token", "credential", "auth", "private_key", "public_key", "shared_secret", "certificate", "keystore", "truststore"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var_name_lower := lower(var.name)
    keyword := sensitive_keywords[_]
    glitch_lib.contains(var_name_lower, keyword)
    var.value.ir_type == "String"
    not glitch_lib.traverse_var(var)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid storing credentials directly in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr_name_lower := lower(attr.name)
    keyword := sensitive_keywords[_]
    glitch_lib.contains(attr_name_lower, keyword)
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid storing credentials directly in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    key_name := lower(pair.key.value)
    keyword := sensitive_keywords[_]
    glitch_lib.contains(key_name, keyword)
    pair.value.ir_type == "String"
    not glitch_lib.traverse_var(pair.value)
    result := {
        "type": "sec_hard_secr",
        "element": pair.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid storing credentials directly in code. (CWE-798)"
    }
}