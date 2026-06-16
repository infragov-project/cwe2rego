package glitch

import data.glitch_lib

sensitive_attributes := {"password", "secret", "key", "token", "credential", "auth", "passphrase", "api_key", "secret_key", "access_key", "private_key", "client_secret", "db_password", "root_password", "admin_password", "ssh_key", "jwt_secret", "user"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    some keyword
    sensitive_attributes[keyword]
    glitch_lib.contains(var.name, keyword)
    var.value.ir_type == "String"
    var.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable default - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    some keyword
    sensitive_attributes[keyword]
    glitch_lib.contains(attr.name, keyword)
    attr.value.ir_type == "String"
    attr.value.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in resource configuration - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    node.value[key_expr] = value_expr
    key_expr.ir_type == "String"
    some keyword
    sensitive_attributes[keyword]
    glitch_lib.contains(key_expr.value, keyword)
    value_expr.ir_type == "String"
    value_expr.value != ""
    result := {
        "type": "sec_hard_secr",
        "element": {"key": key_expr, "value": value_expr},
        "path": parent.path,
        "description": "Hard-coded credential in nested configuration - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}