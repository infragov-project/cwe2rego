package glitch

import data.glitch_lib

# Check for primitive string values directly in variables (Ansible/Vars)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "String"
    var.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Configuration binds to public IP address (0.0.0.0). (CWE-284)"
    }
}

# Check for primitive string values directly in attributes (Ansible/Atomic Units)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Configuration binds to public IP address (0.0.0.0). (CWE-284)"
    }
}

# Check for primitive string values in attributes within Atomic Units (General)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Configuration binds to public IP address (0.0.0.0). (CWE-284)"
    }
}

# Check for nested Hash values (Chef/Puppet) containing "0.0.0.0"
# We must check both keys and values recursively
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # 1. Check Variables in the scope (e.g., Chef attributes, Puppet variables)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Walk the variable's value to find any nested String with "0.0.0.0"
    walk(var.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Configuration binds to public IP address (0.0.0.0) in nested configuration. (CWE-284)"
    }
}

# 2. Check Attributes in the scope (similar logic for attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    walk(attr.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Configuration binds to public IP address (0.0.0.0) in nested configuration. (CWE-284)"
    }
}

# 3. Check Atomic Units (nested attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    walk(attr.value, [path, nested_node])
    nested_node.ir_type == "String"
    nested_node.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": nested_node,
        "path": parent.path,
        "description": "Improper Access Control - Configuration binds to public IP address (0.0.0.0) in nested configuration. (CWE-284)"
    }
}