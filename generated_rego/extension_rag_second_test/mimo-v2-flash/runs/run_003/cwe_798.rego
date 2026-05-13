package glitch

import data.glitch_lib

sensitive_keywords := {"password", "pass", "pwd", "secret", "key", "token", "auth", "credential", "api_secret", "secret_key", "admin_password", "master_password", "sha512_password"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "Attribute"
    name_lower := lower(node.name)
    
    keyword := sensitive_keywords[_]
    contains(name_lower, keyword)
    
    node.value.ir_type == "String"
    value := node.value.value
    value != ""
    not regex.match("^\\$\\{.*\\}$", value)
    not regex.match("^\\$[0-9]+\\$", value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Sensitive authentication data is defined directly within the code or static configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "Variable"
    name_lower := lower(node.name)
    
    keyword := sensitive_keywords[_]
    contains(name_lower, keyword)
    
    node.value.ir_type == "String"
    value := node.value.value
    value != ""
    not regex.match("^\\$\\{.*\\}$", value)
    not regex.match("^\\$[0-9]+\\$", value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Sensitive authentication data is defined directly within the code or static configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "Hash"
    hash_value := node.value
    is_array(hash_value)
    
    item := hash_value[_]
    item.ir_type == "KeyValue"
    name_lower := lower(item.name)
    
    keyword := sensitive_keywords[_]
    contains(name_lower, keyword)
    
    item.value.ir_type == "String"
    value := item.value.value
    value != ""
    not regex.match("^\\$\\{.*\\}$", value)
    not regex.match("^\\$[0-9]+\\$", value)
    
    result := {
        "type": "sec_hard_secr",
        "element": item,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Sensitive authentication data is defined directly within the code or static configuration files. (CWE-798)"
    }
}