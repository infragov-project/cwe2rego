package glitch

import data.glitch_lib

# Check if a variable name indicates an IP address field
is_ip_variable(name) {
    regex.match("(?i)addr|address|ip|bind|listen", name)
}

# Check if a value represents an unrestricted IP
is_unrestricted_value(val) {
    val.ir_type == "String"
    val.value == "0.0.0.0"
}

is_unrestricted_value(val) {
    val.ir_type == "String"
    val.value == "*"
}

is_unrestricted_value(val) {
    val.ir_type == "String"
    val.value == ""
}

# Detect unrestricted IP in Variables (direct assignment)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]

    is_ip_variable(var.name)
    is_unrestricted_value(var.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable configured with unrestricted IP. (CWE-1327)"
    }
}

# Detect unrestricted IP in Hash values within Variables (Chef/Puppet nested configs)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]

    var.value.ir_type == "Hash"
    walk(var.value, [path, node])
    node.key.ir_type == "VariableReference"
    is_ip_variable(node.key.value)
    is_unrestricted_value(node.value)

    result := {
        "type": "sec_invalid_bind",
        "element": node.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Nested hash value configured with unrestricted IP. (CWE-1327)"
    }
}

# Detect unrestricted IP in Hash values with String keys within Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]

    var.value.ir_type == "Hash"
    walk(var.value, [path, node])
    node.key.ir_type == "String"
    is_ip_variable(node.key.value)
    is_unrestricted_value(node.value)

    result := {
        "type": "sec_invalid_bind",
        "element": node.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Nested hash value configured with unrestricted IP. (CWE-1327)"
    }
}

# Detect unrestricted IP in Attributes (Ansible, Chef resources)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_ip_variable(attr.name)
    is_unrestricted_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Attribute configured with unrestricted IP. (CWE-1327)"
    }
}