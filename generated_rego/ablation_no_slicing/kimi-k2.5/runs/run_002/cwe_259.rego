package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "pwd", "pass", "secret", "auth_secret", "client_secret", "credentials", "creds", "auth_token", "api_key", "apikey", "access_key", "secret_key", "private_key", "ssh_key", "key_data", "master_password", "root_password", "admin_password", "token", "bearer_token", "access_token", "connection_string", "conn_string", "sha512_password", "keystore_password", "truststore_password", "key", "auth"}

secret_management_refs := {"data_source", "lookup", "parameter", "variable", "secrets_manager", "vault", "key_vault", "kms", "environment", "env_var", "external_data", "remote_state", "defined", "epp", "data", "vars", "hostvars", "groups"}

contains_password_keyword(name) {
    lower_name := lower(name)
    kw := password_keywords[_]
    lower_name == kw
}

contains_password_keyword(name) {
    lower_name := lower(name)
    kw := password_keywords[_]
    startswith(lower_name, sprintf("%s_", [kw]))
}

contains_password_keyword(name) {
    lower_name := lower(name)
    kw := password_keywords[_]
    endswith(lower_name, sprintf("_%s", [kw]))
}

contains_password_keyword(name) {
    lower_name := lower(name)
    kw := password_keywords[_]
    regex.match(sprintf(".*[._\\-\\['\\]](%s)[._\\-\\[\\]'()].*|^(%s)$|(%s)[._\\-\\['\\(]", [kw, kw, kw]), lower_name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not is_secret_management_reference(value.value)
    not glitch_lib.has_variable_reference(value)
}

is_secret_management_reference(str) {
    lower_str := lower(str)
    ref := secret_management_refs[_]
    contains(lower_str, ref)
}

# Recursively find password keywords in nested structures
find_hardcoded_passwords(root) = results {
    results := [res |
        walk(root, [path, node])
        
        # Check if node is a Hash entry with key-value pair
        node.ir_type == "Hash"
        entry := node.value[_]
        
        # Entry is an object with key and value fields
        entry.key.ir_type == "String"
        key_name := entry.key.value
        contains_password_keyword(key_name)
        
        # Value is a hardcoded String
        entry.value.ir_type == "String"
        is_hardcoded_string(entry.value)
        
        res := {"key_name": key_name, "value_node": entry.value}
    ]
}

# Check for env-style arrays like ["KEY=value", "PASSWORD=secret"]
find_env_style_passwords(arr) = results {
    arr.ir_type == "Array"
    results := [res |
        item := arr.value[_]
        item.ir_type == "String"
        
        val := item.value
        contains(val, "=")
        
        parts := split(val, "=")
        count(parts) >= 2
        
        before_eq := parts[0]
        contains_password_keyword(before_eq)
        not is_secret_management_reference(val)
        
        res := {"key_name": before_eq, "value_node": item}
    ]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk the entire structure to find all nodes
    walk(parent, [_, node])
    
    # Case: Variable with direct hardcoded password
    node.ir_type == "Variable"
    contains_password_keyword(node.name)
    is_hardcoded_string(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    # Find passwords in nested Hash structure
    found := find_hardcoded_passwords(node.value)
    cand := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": cand.value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Array"
    
    # Check for env-style password declarations
    found := find_env_style_passwords(node.value)
    cand := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": cand.value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    # Direct password in attribute
    contains_password_keyword(node.name)
    is_hardcoded_string(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    # Find passwords in nested Hash within attribute value
    found := find_hardcoded_passwords(node.value)
    cand := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": cand.value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Array"
    
    # Check for env-style password declarations in attributes
    found := find_env_style_passwords(node.value)
    cand := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": cand.value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

# Handle Chef-style conditional statements with variable assignments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, parent_node])
    
    parent_node.ir_type == "ConditionalStatement"
    
    walk(parent_node, [_, node])
    node.ir_type == "Variable"
    
    contains_password_keyword(node.name)
    is_hardcoded_string(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

# Handle deeply nested Arrays containing Hashes (like mongodb_users)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Array"
    
    item := node.value.value[_]
    item.ir_type == "Hash"
    
    found := find_hardcoded_passwords(item)
    cand := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": cand.value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}

# Handle nested Arrays within Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Array"
    
    item := node.value.value[_]
    item.ir_type == "Hash"
    
    found := find_hardcoded_passwords(item)
    cand := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": cand.value_node,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hard-coded in configuration, use secure secrets management instead. (CWE-259)"
    }
}