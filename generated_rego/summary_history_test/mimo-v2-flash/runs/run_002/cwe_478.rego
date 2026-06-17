package glitch

import data.glitch_lib
import future.keywords.in

has_default_in_chain(conditional) = result {
    conditional.is_default == true
    result := true
} else {
    conditional.else_statement != null
    result := has_default_in_chain(conditional.else_statement)
} else {
    result := false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    
    conditional.is_top == true
    conditional.is_default == false
    conditional.type == "SWITCH"
    
    not has_default_in_chain(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Switch statement without default case - Missing default case in switch expression can lead to unhandled cases. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    
    conditional.is_top == true
    conditional.type == "IF"
    conditional.else_statement == null
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Conditional statement without default case - Missing default case in conditional expression can lead to unhandled cases. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    function_calls := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
    }
    
    func_call := function_calls[_]
    func_name_lower := lower(func_call.name)
    
    (func_name_lower == "lookup") | (func_name_lower == "hiera") | (func_name_lower == "find_in_map")
    count(func_call.args) < 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": func_call,
        "path": parent.path,
        "description": "Lookup function without default value - Missing default value in lookup can cause failures for undefined keys. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    method_calls := {n |
        walk(parent, [path, n])
        n.ir_type == "MethodCall"
    }
    
    method_call := method_calls[_]
    method_name_lower := lower(method_call.method)
    
    (method_name_lower == "lookup") | (method_name_lower == "hiera") | (method_name_lower == "find_in_map")
    count(method_call.args) < 1
    
    result := {
        "type": "sec_no_default_switch",
        "element": method_call,
        "path": parent.path,
        "description": "Lookup method without default value - Missing default value in lookup can cause failures for undefined keys. (CWE-478)"
    }
}