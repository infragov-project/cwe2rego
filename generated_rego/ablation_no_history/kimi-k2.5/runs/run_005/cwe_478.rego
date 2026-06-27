package glitch

import data.glitch_lib

SWITCH_TYPE := 2
IF_TYPE := 1

is_terminal_default(cond) {
    cond.is_default == true
}

is_terminal_default(cond) {
    cond.condition.ir_type == "Null"
}

find_last_else(cond) = last {
    not cond.else_statement
    last = cond
} else = last {
    cond.else_statement.ir_type != "ConditionalStatement"
    last = cond
} else = last {
    last = find_last_else(cond.else_statement)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "ConditionalStatement"
    node.type == SWITCH_TYPE
    node.is_top == true
    
    not is_terminal_default(node)
    
    last = find_last_else(node)
    not is_terminal_default(last)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch without a default branch may leave cases unhandled, leading to undefined behavior. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "ConditionalStatement"
    node.type == IF_TYPE
    node.is_top == true
    
    not is_terminal_default(node)
    
    last = find_last_else(node)
    not is_terminal_default(last)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in if-else chain - Conditional chain without final fallback may leave cases unhandled. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    regex.match("^(lookup|get|fetch|find|index|coalesce|try|dig)$", node.name)
    count(node.args) < 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": sprintf("Missing default case in %s function - Function call without sufficient arguments may lack proper fallback handling. (CWE-478)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    regex.match("^(lookup|get|fetch|find|index|coalesce|try|dig)$", node.method)
    count(node.args) < 1
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": sprintf("Missing default case in %s method call - Method call without sufficient arguments may lack proper fallback handling. (CWE-478)", [node.method])
    }
}