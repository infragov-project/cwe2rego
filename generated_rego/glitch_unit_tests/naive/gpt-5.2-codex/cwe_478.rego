package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]

    count({1 |
        other := conds[_]
        other.else_statement == cond
    }) == 0

    cond.else_statement != null

    chain := {n |
        walk(cond, [path, n])
        n.ir_type == "ConditionalStatement"
        count({v |
            v := path[_]
            v != "else_statement"
        }) == 0
    }

    count({1 |
        n := chain[_]
        n.is_default == true
    }) == 0

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default/catch-all branch in multi-condition expression. (CWE-478)"
    }
}