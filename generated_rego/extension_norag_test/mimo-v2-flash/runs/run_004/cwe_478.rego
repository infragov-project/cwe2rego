package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == 2
    node.is_top == true
    
    # Check for default case in the chain by walking the else_statement chain recursively
    not has_default_in_chain(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Switch statement without default case - Missing default case in switch statement can lead to unhandled cases. (CWE-478)"
    }
}

has_default_in_chain(node) {
    node.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    has_default_in_chain(node.else_statement)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    lookup_keywords := {"lookup", "get", "fetch"}
    node.name in lookup_keywords
    count(node.args) == 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Lookup function without default value - Missing default value in lookup function can lead to unhandled missing keys. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "MethodCall"
    lookup_keywords := {"lookup", "get", "fetch"}
    node.method in lookup_keywords
    count(node.args) == 1
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Lookup method without default value - Missing default value in lookup method can lead to unhandled missing keys. (CWE-478)"
    }
}