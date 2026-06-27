package glitch

import data.glitch_lib
import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    
    node.is_top == true
    not has_default_in_chain(node)
    count_branches(node) > 1
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statements should have a default case to handle unexpected values. (CWE-478)"
    }
}

count_branches(node) = n {
    n := count(collect_branches(node))
}

collect_branches(start) = branches {
    branches := {b |
        some node in walk_branches(start)
        node.ir_type == "ConditionalStatement"
        node.type == "SWITCH"
        b := node
    }
}

walk_branches(start) = nodes {
    nodes := {node |
        walk(start, [_, node])
        node.ir_type == "ConditionalStatement"
    }
}

has_default_in_chain(start) {
    some node in walk_branches(start)
    node.is_default == true
    node.type == "SWITCH"
}