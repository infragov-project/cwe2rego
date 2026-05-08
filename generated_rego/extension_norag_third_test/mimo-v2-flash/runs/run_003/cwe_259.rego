package glitch

import data.glitch_lib

sensitive_names := {"password", "pass", "pwd", "secret", "token", "api_key", "access_key", "secret_key", "admin_password", "db_password", "root_password", "encryption_key", "keystore_password", "truststore_password", "truststorePassword", "keystorePassword", "truststore_pass", "keystore_pass"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower_node_name := lower(node.name)
    sensitive := sensitive_names[_]
    contains(lower_node_name, lower(sensitive))
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    lower_node_name := lower(node.name)
    sensitive := sensitive_names[_]
    contains(lower_node_name, lower(sensitive))
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
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
    lower_key := lower(key.value)
    sensitive := sensitive_names[_]
    contains(lower_key, lower(sensitive))
    value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": key,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}