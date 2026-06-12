package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent unit block
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Match variable names that suggest address binding
    regex.match("(?i).*(bind|ip|address|endpoint|listen|addr).*", var.name)
    
    # Check for the vulnerable value
    var.value.ir_type == "String"
    var.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Open bind address - Service is bound to all interfaces (0.0.0.0), which may expose it unnecessarily. (CWE-923)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent unit block
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    # Match attribute names that suggest address binding
    regex.match("(?i).*(bind|ip|address|endpoint|listen|addr).*", attr.name)
    
    # Check for the vulnerable value
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Open bind address - Service is bound to all interfaces (0.0.0.0), which may expose it unnecessarily. (CWE-923)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all hash nodes in the parent unit block
    hash_nodes := {n | walk(parent, [path, n]); n.ir_type == "Hash"}
    hash_node := hash_nodes[_]
    
    # Iterate through key-value pairs in the hash
    pair := hash_node.value[_]
    key := pair.key
    value := pair.value
    
    # Match hash keys that suggest address binding
    key.ir_type == "String"
    regex.match("(?i).*(bind|ip|address|endpoint|listen|addr).*", key.value)
    
    # Check for the vulnerable value
    value.ir_type == "String"
    value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "description": "Open bind address - Service is bound to all interfaces (0.0.0.0), which may expose it unnecessarily. (CWE-923)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all hash nodes in the parent unit block
    hash_nodes := {n | walk(parent, [path, n]); n.ir_type == "Hash"}
    hash_node := hash_nodes[_]
    
    # Iterate through key-value pairs in the hash
    pair := hash_node.value[_]
    key := pair.key
    value := pair.value
    
    # Match hash keys that are variable references suggesting address binding
    key.ir_type == "VariableReference"
    regex.match("(?i).*(bind|ip|address|endpoint|listen|addr).*", key.value)
    
    # Check for the vulnerable value
    value.ir_type == "String"
    value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": value,
        "path": parent.path,
        "description": "Open bind address - Service is bound to all interfaces (0.0.0.0), which may expose it unnecessarily. (CWE-923)"
    }
}