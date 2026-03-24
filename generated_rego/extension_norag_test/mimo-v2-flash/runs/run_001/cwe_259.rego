package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "token", "api_key", "db_password", "connection_string", "keystore_password", "truststore_password", "sha512_password", "passwd", "pwd", "admin_password", "key"}

contains_hardcoded_password(node) {
    walk(node, [path, subnode])
    subnode.ir_type == "String"
    not glitch_lib.has_variable_reference(subnode)
    some i
    i < count(path)
    is_string(path[i])
    lower_key := lower(path[i])
    sensitive_keywords[lower_key]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    lower_name := lower(var.name)
    some keyword in sensitive_keywords
    contains(lower_name, keyword)
    var.value.ir_type == "String"
    not glitch_lib.has_variable_reference(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_hardcoded_password(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    some keyword in sensitive_keywords
    contains(lower_name, keyword)
    attr.value.ir_type == "String"
    not glitch_lib.has_variable_reference(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_hardcoded_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in IaC script - Avoid using hard-coded passwords and secrets. (CWE-259)"
    }
}