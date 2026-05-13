package glitch

import data.glitch_lib

# Helper to check if a string value is a public IP binding
is_public_ip(value) {
    value.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|::/0)$", value.value)
}

# Rule to detect public IP binding in direct variables (Ansible style)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)
    is_public_ip(variable.value)
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": sprintf("Improper Access Control - Public IP binding detected in variable '%s' at line %d", [variable.name, variable.line])
    }
}

# Rule to detect public IP binding in attributes (Ansible/Chef/Puppet resources)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_public_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Improper Access Control - Public IP binding detected in attribute '%s' at line %d", [attr.name, attr.line])
    }
}

# Rule to detect public IP binding in hash entries (Chef style variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    node.value[_].value.ir_type == "String"
    is_public_ip(node.value[_].value)
    result := {
        "type": "sec_invalid_bind",
        "element": node.value[_].value,
        "path": parent.path,
        "description": sprintf("Improper Access Control - Public IP binding detected in hash entry at line %d", [node.value[_].value.line])
    }
}

# Rule to detect hardcoded credentials in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)
    variable.name != ""
    variable.value.ir_type == "String"
    variable.value.value != ""
    not regex.match("^(?:/|\\.|[a-zA-Z]:)", variable.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": sprintf("Improper Access Control - Hardcoded credential detected in variable '%s' at line %d", [variable.name, variable.line])
    }
}

# Rule to detect hardcoded credentials in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    attr.name != ""
    attr.value.ir_type == "String"
    attr.value.value != ""
    not regex.match("^(?:/|\\.|[a-zA-Z]:)", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Improper Access Control - Hardcoded credential detected in attribute '%s' at line %d", [attr.name, attr.line])
    }
}