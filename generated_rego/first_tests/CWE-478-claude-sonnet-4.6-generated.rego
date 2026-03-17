package glitch

import data.glitch_lib

lookup_functions := {"lookup", "find_in_map", "findInMap"}

chain_has_default(cond) {
    walk(cond, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

has_default_attribute(unit) {
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    attr.name == "default"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    cond.is_top == true
    cond.else_statement != null
    not chain_has_default(cond)
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Conditional chain with multiple branches lacks a default/else branch to handle unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    node.name == lookup_functions[_]
    count(node.args) < 3
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing Default Case - Lookup/map function called without a default fallback argument, which may fail on unexpected keys. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_units := glitch_lib.all_atomic_units(parent)
    unit := all_units[_]
    glitch_lib.contains(unit.type, "variable")
    nested_units := glitch_lib.all_atomic_units(unit)
    nested := nested_units[_]
    glitch_lib.contains(nested.type, "validation")
    not has_default_attribute(unit)
    result := {
        "type": "sec_no_default_switch",
        "element": unit,
        "path": parent.path,
        "description": "Missing Default Case - Variable with validation constraint has no default value, leaving unspecified states without handling. (CWE-478)"
    }
}