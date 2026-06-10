package glitch

import data.glitch_lib

unrestricted_strings := {"0.0.0.0", "0.0.0.0/0"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Walk through the variable value to find unrestricted strings
    walk(var.value, [_, node])
    node.ir_type == "String"
    node.value in unrestricted_strings
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network access detected (bind address 0.0.0.0) - May allow unauthorized access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    # Walk through the attribute value to find unrestricted strings
    walk(attr.value, [_, node])
    node.ir_type == "String"
    node.value in unrestricted_strings
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access detected (bind address 0.0.0.0) - May allow unauthorized access. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check atomic units for unrestricted strings in their attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    
    # Get attributes of the atomic unit
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    # Walk through the attribute value
    walk(attr.value, [_, node])
    node.ir_type == "String"
    node.value in unrestricted_strings
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access detected (bind address 0.0.0.0) - May allow unauthorized access. (CWE-284)"
    }
}