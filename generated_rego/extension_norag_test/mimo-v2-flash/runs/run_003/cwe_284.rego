package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in the parent
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Walk through the variable's value to find strings
    walk(var.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Insecure network exposure - Service binds to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Walk through the attribute's value to find strings
    walk(attr.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Insecure network exposure - Service binds to all interfaces (0.0.0.0). (CWE-284)"
    }
}