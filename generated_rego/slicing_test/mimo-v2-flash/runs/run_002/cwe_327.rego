package glitch

import data.glitch_lib

# List of weak cryptographic patterns (algorithms, hash functions, key names)
weak_patterns := {"des", "3des", "triple des", "tdea", "rc2", "rc4", "blowfish", "aes-128", "rsa-1024", "ecb", "sha1", "md5", "hmac-md5", "hmac-sha1", "md5_crypt", "tls_rsa_with_aes_128"}

# Helper to check if a string contains a weak pattern (case-insensitive)
contains_weak_pattern(str) {
    regex.match(sprintf("(?i)\\b(%s)\\b", [concat("|", weak_patterns)]), str)
}

# Rule 1: Check Attributes directly (Ansible, Chef, Puppet)
# This handles simple key-value pairs where the value is a string containing a weak algorithm
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Attributes within the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check attribute name (e.g., "encrypt")
    contains_weak_pattern(attr.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - The application uses a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

# Rule 2: Check Attribute values for weak patterns
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute value is a string containing a weak pattern
    attr.value.ir_type == "String"
    contains_weak_pattern(attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - The application uses a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

# Rule 3: Check Variables (Chef) inside ConditionalStatements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable value is a string containing a weak pattern
    var.value.ir_type == "String"
    contains_weak_pattern(var.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - The application uses a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

# Rule 4: Check nested Hash values inside Attributes (e.g., Ansible vars_prompt with "encrypt: md5_crypt")
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # The attribute value is an Array of Hashes (like vars_prompt)
    attr.value.ir_type == "Array"
    
    # Walk through the array to find Hash elements
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    key_val := node.value[_]
    key_val.key.ir_type == "String"
    
    # Check if the key is "encrypt" and the value contains a weak pattern
    key_val.key.value == "encrypt"
    key_val.value.ir_type == "String"
    contains_weak_pattern(key_val.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - The application uses a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

# Rule 5: Check Access expressions (e.g., Chef: jenkins_user_data['password_md5'])
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through the parent to find Access nodes
    walk(parent, [_, node])
    node.ir_type == "Access"
    
    # Check if the right side (key) contains a weak pattern
    node.right.ir_type == "String"
    contains_weak_pattern(node.right.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - The application uses a broken or risky cryptographic algorithm. (CWE-327)"
    }
}