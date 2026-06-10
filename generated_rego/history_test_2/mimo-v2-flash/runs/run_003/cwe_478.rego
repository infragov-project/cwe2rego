package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    top_conditions := {cs | conditions[cs]; cs.is_top; cs.type == "IF"}
    top_condition := top_conditions[_]
    not top_condition.else_statement
    result := {
        "type": "sec_no_default_switch",
        "element": top_condition,
        "path": parent.path,
        "description": "Missing default case in conditional statement - This may lead to unhandled cases and undefined behavior. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    top_conditions := {cs | conditions[cs]; cs.is_top; cs.type == "SWITCH"}
    top_condition := top_conditions[_]
    default_exists := {s | top_condition.statements[s]; s.ir_type == "ConditionalStatement"; s.is_default}
    count(default_exists) == 0
    result := {
        "type": "sec_no_default_switch",
        "element": top_condition,
        "path": parent.path,
        "description": "Missing default case in switch statement - This may lead to unhandled cases and undefined behavior. (CWE-478)"
    }
}