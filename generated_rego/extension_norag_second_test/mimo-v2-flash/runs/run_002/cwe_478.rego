package glitch

import data.glitch_lib

has_default_case(cond) {
    cond.is_default == true
} else {
    cond.else_statement != null
    has_default_case(cond.else_statement)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_top == true
    cond.type == "SWITCH"
    not has_default_case(cond)
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch logic lacks a fallback handler for unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_top == true
    cond.type == "IF"
    cond.else_statement == null
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing else branch in if statement - Conditional logic lacks a fallback handler for unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "FunctionCall"
    node.name == "lookup"
    count(node.args) < 3
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default value in lookup function - Function call lacks fallback parameter for unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "FunctionCall"
    node.name == "coalesce"
    count(node.args) < 2
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default value in coalesce function - Function call lacks fallback parameter for unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "FunctionCall"
    node.name == "try"
    count(node.args) < 2
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default value in try function - Function call lacks fallback parameter for unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "MethodCall"
    regex.match("(?i)each|for_each|foreach|map|filter|reduce", node.method)
    count(node.args) > 0
    arg := node.args[0]
    arg.ir_type == "BlockExpr"
    loop_conditions := glitch_lib.all_conditional_statements(arg)
    count(loop_conditions) > 0
    # Check that none of the conditions are default using set comprehension
    default_count := count({lc | lc in loop_conditions; lc.is_default == true})
    default_count == 0
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in iteration loop - Loop lacks fallback handler for unexpected items. (CWE-478)"
    }
}