package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "pwd", "secret", "token", "key", "credential"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := glitch_lib.all_variables(parent)
    all_attrs := glitch_lib.all_attributes(parent)
    key_values := all_vars | all_attrs
    
    kv := key_values[_]
    kv.value.ir_type == "String"
    kv.value.value == ""
    
    name_lower := lower(kv.name)
    keyword := password_keywords[_]
    contains(name_lower, keyword)
    
    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_strings := {node |
        walk(parent, [path, node])
        node.ir_type == "String"
    }
    
    some str_node
    all_strings[str_node]
    regex.match(`(?i)(pwd|password|token|secret|key|credential)=(?:[;&]|$)`, str_node.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": str_node,
        "path": parent.path,
        "description": "Empty password in connection string - Passwords should not be empty. (CWE-258)"
    }
}