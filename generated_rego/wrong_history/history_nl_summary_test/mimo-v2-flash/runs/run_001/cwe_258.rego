package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass"}

is_password_field(name) {
    keyword := password_keywords[_]
    contains(name, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

# Check for empty password in variables (Ansible vars, Chef attributes, etc.)
Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    variables := glitch_lib.all_variables(unit_block)
    var := variables[_]
    
    is_password_field(var.name)
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}

# Check for empty password in atomic unit attributes (Puppet resources, Chef resources, etc.)
Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(unit_block)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_password_field(attr.name)
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}

# Check for empty password in unit block attributes (Puppet class parameters, etc.)
Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    attrs := glitch_lib.all_attributes(unit_block)
    attr := attrs[_]
    
    is_password_field(attr.name)
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}

# Check for empty password in function calls that reference empty variables (Puppet function calls)
Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    # Get all empty variables in the unit block
    empty_vars := {var.name |
        var := glitch_lib.all_variables(unit_block)[_]
        is_empty_value(var.value)
    }
    
    # Check atomic units for function calls that reference empty variables
    atomic_units := glitch_lib.all_atomic_units(unit_block)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    
    # Check if any argument of the function call is a variable reference to an empty variable
    arg := func_call.args[_]
    arg.ir_type == "VariableReference"
    empty_vars[arg.value]
    
    # Check if the attribute name or function name indicates a password context
    is_password_field(attr.name) or is_password_field(func_call.name)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}