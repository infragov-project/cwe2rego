package glitch

import data.glitch_lib

password_pattern := "(?i)(password|pass|passwd|secret|token|credential|key)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    
    # Check for Hash nodes (like in Ansible YAML/JSON structures)
    node.ir_type == "Hash"
    kv := node.value[_]
    key := kv.key
    key.ir_type == "String"
    regex.match(password_pattern, key.value)
    
    value := kv.value
    value.ir_type == "String"
    not glitch_lib.has_variable_reference(value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password in Infrastructure as Code (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    
    # Check for Variable nodes (like in Chef attributes)
    node.ir_type == "Variable"
    regex.match(password_pattern, node.name)
    
    value := node.value
    value.ir_type == "String"
    not glitch_lib.has_variable_reference(value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password in Infrastructure as Code (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    
    # Check for Array elements that are Hashes with password keys (like in Ansible list of users)
    node.ir_type == "Array"
    array_element := node.value[_]
    array_element.ir_type == "Hash"
    
    kv := array_element.value[_]
    key := kv.key
    key.ir_type == "String"
    regex.match(password_pattern, key.value)
    
    value := kv.value
    value.ir_type == "String"
    not glitch_lib.has_variable_reference(value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password in Infrastructure as Code (CWE-259)"
    }
}