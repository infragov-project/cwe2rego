package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the unit block
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check for credential-related variable names
    credential_keywords := {"password", "secret", "key", "token", "credential", "passwd", "pwd"}
    name_lower := lower(var.name)
    
    # Check if variable name contains any credential keyword
    contains_credential := false
    some keyword
    credential_keywords[keyword]
    contains(name_lower, keyword)
    
    # Check if the value is a string (hard-coded)
    var.value.ir_type == "String"
    
    # Additional check: avoid common secure patterns (e.g., variable references)
    not is_secure_pattern(var.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hard-coded credential found in variable: %s", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the unit block
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    # Check for credential-related attribute names
    credential_keywords := {"password", "secret", "key", "token", "credential", "passwd", "pwd"}
    name_lower := lower(attr.name)
    
    # Check if attribute name contains any credential keyword
    contains_credential := false
    some keyword
    credential_keywords[keyword]
    contains(name_lower, keyword)
    
    # Check if the value is a string (hard-coded)
    attr.value.ir_type == "String"
    
    # Additional check: avoid common secure patterns
    not is_secure_pattern(attr.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded credential found in attribute: %s", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for nested key-value pairs in complex structures (e.g., Hash within Hash)
    walk(parent, [path, node])
    node.ir_type == "String"
    
    # Check if the parent of this string is a key-value pair with credential keyword
    count(path) > 0
    parent_node := get_parent_node(parent, path)
    
    # Check if parent_node has a key field with credential keyword
    parent_node.key.ir_type == "String"
    key_name := lower(parent_node.key.value)
    
    credential_keywords := {"password", "secret", "key", "token", "credential", "passwd", "pwd"}
    contains_credential := false
    some keyword
    credential_keywords[keyword]
    contains(key_name, keyword)
    
    # Check if the value is a string (hard-coded)
    node.ir_type == "String"
    
    # Additional check: avoid common secure patterns
    not is_secure_pattern(node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded credential found in nested structure: %s", [parent_node.key.value])
    }
}

# Helper function to check if a string value represents a secure pattern
is_secure_pattern(value) {
    # Check if it's a variable reference (e.g., {{ variable }}, ${var}, etc.)
    regex.match(".*[{]{2}.*[}]{2}.*", value)
}

is_secure_pattern(value) {
    # Check if it's an environment variable reference
    regex.match(".*\\$\\{.*\\}.*", value)
}

is_secure_pattern(value) {
    # Check if it's a function call (e.g., secret(), vault())
    regex.match(".*secret\\(.*\\).*", value)
    regex.match(".*vault\\(.*\\).*", value)
}

is_secure_pattern(value) {
    # Check if it's a reference to a secret manager
    regex.match(".*arn:aws:secretsmanager.*", value)
    regex.match(".*vault.*", value)
}

# Helper function to get parent node from walk path
get_parent_node(node, path) = parent {
    count(path) > 0
    parent_path := path[count(path) - 1]
    walk(node, [parent_path, parent])
}

# Helper function for string containment (case-insensitive)
contains(s, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), s)
}