package glitch

import data.glitch_lib

# Rule 1: Detect unencrypted protocol strings and URLs in String values
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "String"
    regex.match("http://", lower(node.value))
    result := {
        "type": "sec_https",
        "element": node,
        "path": find_parent_path(path),
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol (HTTP) used. (CWE-319)"
    }
}

# Rule 2: Detect unencrypted protocol in Sum nodes (String concatenation)
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Sum"
    glitch_lib.traverse(node, "http://")
    result := {
        "type": "sec_https",
        "element": node,
        "path": find_parent_path(path),
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol (HTTP) used in concatenation. (CWE-319)"
    }
}

# Rule 3: Detect hardcoded secrets in Variables
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Variable"
    secret_keywords := {"password", "secret", "key", "token", "credential", "auth", "apikey", "client_secret", "private_key", "secret_key"}
    secret_keywords[node.name]
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_https",
        "element": node,
        "path": find_parent_path(path),
        "description": "Cleartext transmission of sensitive information - Hardcoded secret in variable. (CWE-319)"
    }
}

# Rule 4: Detect unencrypted ports in Attributes
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Attribute"
    lower(node.name) == "port"
    node.value.ir_type == "Integer"
    unencrypted_ports := {80, 21, 23, 8080}
    unencrypted_ports[node.value.value]
    result := {
        "type": "sec_https",
        "element": node,
        "path": find_parent_path(path),
        "description": "Cleartext transmission of sensitive information - Unencrypted port used. (CWE-319)"
    }
}

# Helper function to extract path from UnitBlock in the hierarchy
find_parent_path(path) = p {
    # Walk up the path to find a UnitBlock
    # Since path is an array of keys, we check if any element in the path array is a UnitBlock
    # But since walk returns path as keys, we need to reconstruct the parent object
    # Simplification: Look for the nearest UnitBlock in the path
    # In GLITCH, the path returned by walk contains keys used to reach the node.
    # We iterate backwards from the end of the path to find the first UnitBlock
    # However, since we cannot iterate arrays easily without comprehensions on the path itself,
    # We use a different approach: check the input structure directly.
    
    # Check if the input itself is a UnitBlock with a path
    input.path != ""
    p := input.path
} else {
    # Fallback: if input is not the top UnitBlock, try to find a UnitBlock parent
    # Since we can't easily walk up in V0 without specific structure, 
    # we assume the input contains the project/module structure.
    # We iterate over modules in the input to find matching path
    # This is a heuristic for the specific IR structure provided.
    
    # Iterate over modules in the input (if input is Project)
    module := input.modules[_]
    module.path != ""
    # Check if the current node path contains the module path
    # Since we don't have the full node path, we can't do this easily.
    # Instead, we rely on the fact that _gather_parent_unit_blocks in glitch_lib
    # provides the parent unit block.
    
    # Correct approach using glitch_lib:
    # Since we are in a walk, we don't have direct access to the parent UnitBlock from glitch_lib
    # without re-traversing. 
    # We will simply return a placeholder or use the input path if available.
    # For this specific task, we will assume the input is the root Project or Module
    # and we extract the path from the first UnitBlock found in the hierarchy.
    
    # This is a limitation of the helper without re-walking.
    # However, for the purpose of the rule, we can define the path in the rule body itself
    # by finding the parent UnitBlock using glitch_lib logic.
    
    # Re-implementation of the rule to use glitch_lib correctly:
    # We cannot use a helper function easily for path extraction inside a walk.
    # We will modify the rules to not use the helper, but directly calculate the path
    # by finding the parent UnitBlock of the current node.
    
    p := "unknown"
}

# Modified Rule 1 to correctly find path
Glitch_Analysis[result] {
    # Find parent unit block using glitch_lib
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find string nodes within this parent
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match("http://", lower(node.value))
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol (HTTP) used. (CWE-319)"
    }
}

# Modified Rule 2 to correctly find path
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Sum"
    glitch_lib.traverse(node, "http://")
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol (HTTP) used in concatenation. (CWE-319)"
    }
}

# Modified Rule 3 to correctly find path
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    secret_keywords := {"password", "secret", "key", "token", "credential", "auth", "apikey", "client_secret", "private_key", "secret_key"}
    secret_keywords[node.name]
    node.value.ir_type == "String"
    node.value.value != ""
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hardcoded secret in variable. (CWE-319)"
    }
}

# Modified Rule 4 to correctly find path
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower(node.name) == "port"
    node.value.ir_type == "Integer"
    unencrypted_ports := {80, 21, 23, 8080}
    unencrypted_ports[node.value.value]
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted port used. (CWE-319)"
    }
}