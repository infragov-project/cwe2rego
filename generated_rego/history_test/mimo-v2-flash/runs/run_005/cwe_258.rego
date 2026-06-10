package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in the parent (e.g., for resource definitions)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if attribute name suggests it's a password/secret field
    regex.match("(?i)(password|passwd|pwd|secret|token|key|credential|auth)", attr.name)
    
    # Check if value is empty string or null
    attr.value.ir_type == "String"
    attr.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password assigned to a sensitive field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in the parent (e.g., variable definitions)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable name suggests it's a password/secret field
    regex.match("(?i)(password|passwd|pwd|secret|token|key|credential|auth)", var.name)
    
    # Check if value is empty string or null
    var.value.ir_type == "String"
    var.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password assigned to a sensitive variable. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for null values in sensitive fields
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if attribute name suggests it's a password/secret field
    regex.match("(?i)(password|passwd|pwd|secret|token|key|credential|auth)", attr.name)
    
    # Check if value is null
    attr.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Null password assigned to a sensitive field. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for null values in sensitive variables
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable name suggests it's a password/secret field
    regex.match("(?i)(password|passwd|pwd|secret|token|key|credential|auth)", var.name)
    
    # Check if value is null
    var.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Null password assigned to a sensitive variable. (CWE-258)"
    }
}