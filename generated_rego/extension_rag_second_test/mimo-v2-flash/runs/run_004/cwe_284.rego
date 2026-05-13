package glitch

import data.glitch_lib

# Rule to detect hardcoded secrets in Ansible variables
Glitch_Analysis[result] {
    walk(input, [path, hash_node])
    hash_node.ir_type == "Hash"
    
    # Check if this hash is inside an array (Ansible list of users)
    walk(input, [array_path, array_node])
    array_node.ir_type == "Array"
    array_node.value[_] == hash_node
    
    # Find password key-value pair in the hash
    item := hash_node.value[_]
    key_node := item.key
    value_node := item.value
    
    # Check if key indicates password
    key_node.ir_type == "String"
    key_node.value == "password"
    
    # Check if value is a hardcoded string (not a lookup)
    value_node.ir_type == "String"
    value_node.value != ""
    
    # Get parent context
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_invalid_bind",
        "element": value_node,
        "path": parent.path,
        "description": "Hardcoded password in Ansible user list - This may expose credentials. (CWE-284)"
    }
}

# Rule to detect public IP binding in Chef hash values
Glitch_Analysis[result] {
    walk(input, [path, hash_node])
    hash_node.ir_type == "Hash"
    
    # Find key-value pair in the hash
    item := hash_node.value[_]
    key_node := item.key
    value_node := item.value
    
    # Check if key indicates IP address binding
    key_node.ir_type == "String"
    regex.match("(?i)ip|address|bind", key_node.value)
    
    # Check if value is a public/unrestricted IP (regex is a raw string)
    value_node.ir_type == "String"
    regex.match("(?i)^(0\\.0\\.0\\.0|\\*|::/0)$", value_node.value)
    
    # Get parent context
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_invalid_bind",
        "element": value_node,
        "path": parent.path,
        "description": "Public IP binding detected in Chef configuration - This may allow unauthorized network access. (CWE-284)"
    }
}

# Rule to detect hardcoded IP in Chef variables (attributes)
Glitch_Analysis[result] {
    walk(input, [path, var_node])
    var_node.ir_type == "Variable"
    var_node.name != ""
    
    # Check if variable name indicates IP or server address
    regex.match("(?i)(addr|address|ip|bind)", var_node.name)
    
    # Check if value is a public IP (regex is a raw string)
    var_node.value.ir_type == "String"
    regex.match("(?i)^(0\\.0\\.0\\.0|\\*|::/0)$", var_node.value.value)
    
    # Get parent context
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_invalid_bind",
        "element": var_node,
        "path": parent.path,
        "description": "Public IP address configured in variable - This may allow unauthorized network access. (CWE-284)"
    }
}