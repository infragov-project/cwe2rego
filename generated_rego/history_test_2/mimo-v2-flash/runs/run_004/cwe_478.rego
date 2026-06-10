package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Detect missing default in mapping/dictionary structures
    hash_nodes := {n |
        walk(parent, [_, n])
        n.ir_type == "Hash"
    }
    hash_node := hash_nodes[_]

    # Check if the hash is used in a control flow context (e.g., assignment or lookup)
    # Look for assignments where the hash is the right-hand side
    walk(parent, [path, assign_node])
    assign_node.ir_type == "Assign"
    assign_node.right == hash_node

    # Ensure the hash does not have a default key
    not has_default_key(hash_node)

    result := {
        "type": "sec_no_default_switch",
        "element": hash_node,
        "path": parent.path,
        "description": "Missing default case in conditional mapping/selection - Ensure fallback behavior for unexpected inputs. (CWE-478)"
    }
}

has_default_key(hash_node) {
    # Check for default, wildcard, or null keys
    key := hash_node.value[_]
    key.ir_type == "String"
    regex.match("(?i)^(default|\\*|null|_)$", key.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Detect missing default in conditional statements
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]

    # Check if it's a top-level conditional without an else branch
    conditional.is_top == true
    not conditional.else_statement

    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in conditional statement - Ensure an else branch for unhandled conditions. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Detect missing fallback in function calls (e.g., lookup without default)
    function_calls := {n |
        walk(parent, [_, n])
        n.ir_type == "FunctionCall"
    }
    func := function_calls[_]

    # Check for lookup-like functions without default parameter
    lookup_pattern := "(?i)^(lookup|get|select|filter)$"
    func.name =~ lookup_pattern

    # Ensure the function call does not have a fallback/default argument
    count(func.args) < 2

    result := {
        "type": "sec_no_default_switch",
        "element": func,
        "path": parent.path,
        "description": "Missing fallback in function call - Ensure lookup functions have a default parameter. (CWE-478)"
    }
}