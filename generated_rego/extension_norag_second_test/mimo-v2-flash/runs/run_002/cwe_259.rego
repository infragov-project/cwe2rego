package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "token", "key", "credential", "pass", "pwd", "admin_password", "root_password", "master_password", "db_password", "api_key", "auth_token", "default", "admin", "root", "administrator", "service_account", "builtin", "initial_password", "setup_credentials", "connection_string", "endpoint", "api_url", "external_service", "third_party", "auth"}

check_string_value(value) {
    value.ir_type == "String"
    value.value != ""
}

check_key_name(key_name) {
    is_string(key_name)
    key_name_lower := lower(key_name)
    some sk
    sensitive_keywords[sk]
    contains(key_name_lower, sk)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    check_key_name(var.name)
    check_string_value(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    check_key_name(attr.name)
    check_string_value(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    check_key_name(pair.key.value)
    check_string_value(pair.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": pair.key,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "String"
    elem.value != ""
    check_key_name(elem.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": elem,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coded passwords in IaC scripts. (CWE-259)"
    }
}