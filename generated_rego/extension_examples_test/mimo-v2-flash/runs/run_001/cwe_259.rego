package glitch

import data.glitch_lib

sensitive_keywords := {"password", "pass", "secret", "key", "token", "credential", "admin_password", "db_password", "api_key", "auth_token"}

contains_sensitive_keyword(name) {
    some keyword
    keyword = sensitive_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

is_static_string(value) {
    value.ir_type == "String"
    value.value != ""
}

check_hash_for_secret(hash_node) {
    hash_node.ir_type == "Hash"
    some kv_pair
    kv_pair = hash_node.value[_]
    key_node := kv_pair.key
    value_node := kv_pair.value
    key_node.ir_type == "String"
    value_node.ir_type == "String"
    contains_sensitive_keyword(key_node.value)
    is_static_string(value_node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    contains_sensitive_keyword(node.name)
    is_static_string(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded secret found in variable '%s'. (CWE-259)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    contains_sensitive_keyword(node.name)
    is_static_string(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded secret found in attribute '%s'. (CWE-259)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    check_hash_for_secret(node)
    
    some kv_pair
    kv_pair = node.value[_]
    key_node := kv_pair.key
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded secret found in hash key '%s'. (CWE-259)", [key_node.value])
    }
}