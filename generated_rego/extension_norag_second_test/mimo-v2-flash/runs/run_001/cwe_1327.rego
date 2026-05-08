package glitch

import data.glitch_lib

# Detect unrestricted IP bindings in Variables and Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check Variables (e.g., Chef attributes, Puppet params)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Match common network binding variable names (case-insensitive)
    network_var_names := {"bind", "bind_address", "ip", "ip_address", "addr", "host", "bind-address", "bind_address"}
    contains_lower(var.name, network_var_names[_])
    
    # Check for unrestricted values
    is_unrestricted_value(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Services should not bind to 0.0.0.0 or equivalent wildcards. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check Attributes in AtomicUnits (e.g., Ansible tasks, Chef resources, Puppet resources)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Match common network binding attribute names (case-insensitive)
    network_attr_names := {"bind", "bind_address", "ip", "ip_address", "addr", "host", "bind-address"}
    contains_lower(attr.name, network_attr_names[_])
    
    # Check for unrestricted values
    is_unrestricted_value(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Services should not bind to 0.0.0.0 or equivalent wildcards. (CWE-1327)"
    }
}

# Helper function to check if a value is unrestricted (0.0.0.0, *, ::, etc.)
is_unrestricted_value(val) {
    # Direct string match
    val.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|\\*|::|all_interfaces|any_address)$", val.value)
}

is_unrestricted_value(val) {
    # Check within Hash values (e.g., nested configurations in Puppet or Chef)
    val.ir_type == "Hash"
    walk(val, [_, node])
    node.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|\\*|::|all_interfaces|any_address)$", node.value)
}

is_unrestricted_value(val) {
    # Check within Array values
    val.ir_type == "Array"
    walk(val, [_, node])
    node.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|\\*|::|all_interfaces|any_address)$", node.value)
}

# Helper: Case-insensitive substring matching
contains_lower(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}