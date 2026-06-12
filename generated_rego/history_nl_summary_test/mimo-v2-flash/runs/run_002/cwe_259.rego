package glitch

import data.glitch_lib

sensitive_keys := {"password", "pass", "secret", "token", "key", "credential", "admin_password", "db_password", "root_password", "connection_string", "api_key", "keystore_password", "truststore_password"}

is_hardcoded_string(node) {
    node.ir_type == "String"
    not glitch_lib.has_variable_reference(node)
    not regex.match(".*\\$\\{.*\\}.*", node.value)
    not regex.match(".*%\\{.*\\}.*", node.value)
}

contains_sensitive_pattern(str) {
    some sensitive_key
    sensitive_keys[sensitive_key]
    glitch_lib.contains(str, sensitive_key)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    
    key_node.ir_type == "String"
    contains_sensitive_pattern(key_node.value)
    
    value_node.ir_type == "String"
    is_hardcoded_string(value_node)
    
    result := {
        "type": "sec_hard_pass",
        "element": value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    is_hardcoded_string(node.value)
    contains_sensitive_pattern(node.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    is_hardcoded_string(node.value)
    contains_sensitive_pattern(node.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Array"
    array_element := node.value.value[_]
    array_element.ir_type == "String"
    is_hardcoded_string(array_element)
    contains_sensitive_pattern(array_element.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": array_element,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}