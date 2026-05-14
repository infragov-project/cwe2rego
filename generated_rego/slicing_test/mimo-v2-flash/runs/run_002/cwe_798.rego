package glitch

import data.glitch_lib

credential_fields = {"password", "pass", "pwd", "secret", "key", "token", "auth", "credential", "api_key", "secret_key", "access_key", "shared_key", "connection_string", "dsn", "uri", "private_key", "public_key", "auth_token", "secret_text", "user"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.name != ""
    var.value.ir_type == "String"
    lower_name := lower(var.name)
    field := credential_fields[_]
    lower_field := lower(field)
    glitch_lib.contains(lower_name, lower_field)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Avoid using hard-coded credentials in IaC. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name != ""
    attr.value.ir_type == "String"
    lower_name := lower(attr.name)
    field := credential_fields[_]
    lower_field := lower(field)
    glitch_lib.contains(lower_name, lower_field)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in attribute - Avoid using hard-coded credentials in IaC. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    key_node := kv.key
    value_node := kv.value
    key_node.ir_type == "String"
    value_node.ir_type == "String"
    key_node.value != ""
    value_node.value != ""
    lower_key := lower(key_node.value)
    field := credential_fields[_]
    lower_field := lower(field)
    glitch_lib.contains(lower_key, lower_field)
    result := {
        "type": "sec_hard_secr",
        "element": value_node,
        "path": parent.path,
        "description": "Hard-coded credential in hash - Avoid using hard-coded credentials in IaC. (CWE-798)"
    }
}