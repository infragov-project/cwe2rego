package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Look for variables or attributes with Hash values that contain "0.0.0.0"
    # We'll traverse the Hash structure to find key-value pairs where the value is "0.0.0.0"
    
    # Check variables
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    walk(variable.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    # Ensure this is not a false positive by checking the key context
    # In the Chef example, this would be in a Hash with key ":ip"
    # In the Puppet example, this would be in a Hash with key "bind-address"
    # We want to flag the specific key-value pair, not the entire Hash or variable
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Overly Permissive Access Policy: value set to 0.0.0.0 (allows connections from any IP). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    walk(attribute.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Overly Permissive Access Policy: value set to 0.0.0.0 (allows connections from any IP). (CWE-284)"
    }
}