package glitch

import data.glitch_lib

# CWE-327: Use of weak or deprecated cryptographic algorithms

# Define weak cryptographic algorithms and hashes
weak_algorithms := {"sha1", "md5", "des", "3des", "rc4", "aes-ecb", "blowfish", "rsa-1024", "md5_crypt", "sha1"}

# Check for weak algorithms in String values
check_weak_algorithm(value) {
    value.ir_type == "String"
    algorithm := lower(value.value)
    weak_algorithms[_] == algorithm
}

# Check for weak algorithms in FunctionCall (e.g., hash filters in Ansible)
check_weak_algorithm(value) {
    value.ir_type == "FunctionCall"
    name := lower(value.name)
    contains(name, "hash")
    args := value.args
    count(args) > 0
    arg := args[count(args) - 1]
    arg.ir_type == "String"
    algorithm := lower(arg.value)
    weak_algorithms[_] == algorithm
}

# Detect weak cryptographic algorithms in Variables (Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Traverse all variables
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    # Check if variable value contains weak algorithm
    check_weak_algorithm(variable.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": variable,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm (CWE-327)"
    }
}

# Detect weak cryptographic algorithms in Attributes (Ansible set_fact, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Traverse all attributes
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    # Check if attribute value contains weak algorithm
    check_weak_algorithm(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm (CWE-327)"
    }
}

# Detect weak algorithms in nested structures (Hash within Array, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes to find nested weak algorithms
    walk(parent, [path, node])
    
    # Check for weak algorithms in String values
    node.ir_type == "String"
    check_weak_algorithm(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm (CWE-327)"
    }
}