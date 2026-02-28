package glitch

import data.glitch_lib

deprecated_algorithms := {"des", "3des", "rc4", "md5", "sha1", "ecb-mode", "plaintext"}
deprecated_key_sizes := {"1024", "2048"}
deprecated_protocols := {"ssl", "tls1.0", "tls1.1", "ssl2", "ssl3"}
weak_ciphers := {"null", "export", "rc4", "des", "3des"}

# Rule for deprecated algorithm in variables (Chef case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    var.value.ir_type == "MethodCall"
    var.value.receiver.ir_type == "VariableReference"
    
    receiver_value := lower(var.value.receiver.value)
    receiver_value == "digest::md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in variables (Chef case - sha1)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    var.value.ir_type == "MethodCall"
    var.value.receiver.ir_type == "VariableReference"
    
    receiver_value := lower(var.value.receiver.value)
    receiver_value == "digest::sha1"
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in function calls (Ansible case - hash filter)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "FunctionCall"
    
    node.name == "filter|hash"
    count(node.args) > 0
    
    algorithm_arg := node.args[count(node.args) - 1]
    algorithm_arg.ir_type == "String"
    
    algorithm_value := lower(algorithm_arg.value)
    algorithm_value == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in function calls (Ansible case - sha1)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "FunctionCall"
    
    node.name == "filter|hash"
    count(node.args) > 0
    
    algorithm_arg := node.args[count(node.args) - 1]
    algorithm_arg.ir_type == "String"
    
    algorithm_value := lower(algorithm_arg.value)
    algorithm_value == "sha1"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in attributes (Ansible case - md5 prefix)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.value.ir_type == "Sum"
    attr.value.left.ir_type == "String"
    
    left_value := lower(attr.value.left.value)
    left_value == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in attributes (Ansible case - sha1 prefix)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.value.ir_type == "Sum"
    attr.value.left.ir_type == "String"
    
    left_value := lower(attr.value.left.value)
    left_value == "sha1"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for weak key sizes in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "key_")
    
    attr.value.ir_type == "String"
    key_size_value := attr.value.value
    key_size_value == "1024"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic key size. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "key_")
    
    attr.value.ir_type == "String"
    key_size_value := attr.value.value
    key_size_value == "2048"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic key size. (CWE-327)"
    }
}

# Rule for insecure protocol versions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "version")
    
    attr.value.ir_type == "String"
    protocol_value := lower(attr.value.value)
    protocol_value == "ssl"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure protocol version. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "protocol")
    
    attr.value.ir_type == "String"
    protocol_value := lower(attr.value.value)
    protocol_value == "ssl"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure protocol version. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "policy")
    
    attr.value.ir_type == "String"
    protocol_value := lower(attr.value.value)
    protocol_value == "ssl"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure protocol version. (CWE-327)"
    }
}

# Rule for weak cipher suites
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "cipher")
    
    attr.value.ir_type == "String"
    cipher_value := lower(attr.value.value)
    cipher_value == "null"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cipher suite. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "cipher")
    
    attr.value.ir_type == "String"
    cipher_value := lower(attr.value.value)
    cipher_value == "export"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cipher suite. (CWE-327)"
    }
}

# Rule for hardcoded cryptographic keys in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "key")
    
    attr.value.ir_type == "String"
    value_length := count(attr.value.value)
    value_length > 5
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded cryptographic key detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "secret")
    
    attr.value.ir_type == "String"
    value_length := count(attr.value.value)
    value_length > 5
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded cryptographic key detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "password")
    
    attr.value.ir_type == "String"
    value_length := count(attr.value.value)
    value_length > 5
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded cryptographic key detected. (CWE-327)"
    }
}

# Rule for insecure password hashing in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "password")
    
    attr.value.ir_type == "String"
    hash_value := lower(attr.value.value)
    hash_value == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure password hashing algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "hash")
    
    attr.value.ir_type == "String"
    hash_value := lower(attr.value.value)
    hash_value == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure password hashing algorithm. (CWE-327)"
    }
}

# Rule for missing cryptographic configuration
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "secure")
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Missing or disabled cryptographic configuration where required. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "encryption")
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Missing or disabled cryptographic configuration where required. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    contains(lower_attr_name, "ssl")
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Missing or disabled cryptographic configuration where required. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell command (Ansible case) - direct check
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "VariableReference"
    
    node.value == "db_password_md5"
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Sum"
    
    # Check for md5 directly in left side
    attr.value.left.ir_type == "String"
    lower(attr.value.left.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell command (Ansible case) - nested check
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "VariableReference"
    
    node.value == "db_password_md5"
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Sum"
    
    # Check for md5 in nested left Sum
    attr.value.left.ir_type == "Sum"
    attr.value.left.left.ir_type == "String"
    lower(attr.value.left.left.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell command (Ansible case) - right side check
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "VariableReference"
    
    node.value == "db_password_md5"
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.ir_type == "Attribute"
    attr.value.ir_type == "Sum"
    
    # Check for md5 in right side
    attr.value.right.ir_type == "String"
    lower(attr.value.right.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell attribute (Ansible case) - left side
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Attribute"
    
    node.name == "shell"
    
    node.value.ir_type == "Sum"
    node.value.left.ir_type == "String"
    contains(lower(node.value.left.value), "md5")
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell attribute (Ansible case) - right side
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Attribute"
    
    node.name == "shell"
    
    node.value.ir_type == "Sum"
    node.value.right.ir_type == "String"
    contains(lower(node.value.right.value), "md5")
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell attribute (Ansible case) - nested left side
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Attribute"
    
    node.name == "shell"
    
    node.value.ir_type == "Sum"
    node.value.left.ir_type == "Sum"
    node.value.left.left.ir_type == "String"
    contains(lower(node.value.left.left.value), "md5")
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell attribute (Ansible case) - nested right side
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Attribute"
    
    node.name == "shell"
    
    node.value.ir_type == "Sum"
    node.value.right.ir_type == "Sum"
    node.value.right.right.ir_type == "String"
    contains(lower(node.value.right.right.value), "md5")
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in Puppet (auth_method => 'md5')
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    lower_attr_name == "auth_method"
    
    attr.value.ir_type == "String"
    lower(attr.value.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in Puppet (function postgresql_password)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "FunctionCall"
    
    node.name == "postgresql_password"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in Puppet (password_hash attribute)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    lower_attr_name := lower(attr.name)
    lower_attr_name == "password_hash"
    
    attr.value.ir_type == "FunctionCall"
    attr.value.name == "postgresql_password"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in Sum values (direct check)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Sum"
    
    # Check left side
    node.left.ir_type == "String"
    lower(node.left.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Sum"
    
    # Check right side
    node.right.ir_type == "String"
    lower(node.right.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in nested Sum values (Ansible case) - left.left
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Sum"
    node.left.ir_type == "Sum"
    
    # Check left.left
    node.left.left.ir_type == "String"
    lower(node.left.left.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in nested Sum values (Ansible case) - left.right
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Sum"
    node.left.ir_type == "Sum"
    
    # Check left.right
    node.left.right.ir_type == "String"
    lower(node.left.right.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in nested Sum values on right side - right.left
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Sum"
    node.right.ir_type == "Sum"
    
    # Check right.left
    node.right.left.ir_type == "String"
    lower(node.right.left.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in nested Sum values on right side - right.right
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "Sum"
    node.right.ir_type == "Sum"
    
    # Check right.right
    node.right.right.ir_type == "String"
    lower(node.right.right.value) == "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell command string (Ansible case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_nodes := {n |
        walk(parent, [path, n])
    }
    
    node := all_nodes[_]
    node.ir_type == "String"
    
    # Check if string contains md5 in shell command context (but not just "md5" standalone)
    contains(lower(node.value), "md5")
    node.value != "md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell attribute (Ansible case) - check for db_password_md5 in shell value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Look for shell attribute
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.ir_type == "Attribute"
    attr.name == "shell"
    
    # Check if the shell value contains reference to db_password_md5
    attr.value.ir_type == "Sum"
    attr.value.right.ir_type == "VariableReference"
    attr.value.right.value == "db_password_md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}

# Rule for deprecated algorithm in shell attribute (Ansible case) - check nested Sum for db_password_md5
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Look for shell attribute
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    attr.ir_type == "Attribute"
    attr.name == "shell"
    
    # Check if the shell value contains reference to db_password_md5 in nested structure
    attr.value.ir_type == "Sum"
    attr.value.right.ir_type == "Sum"
    attr.value.right.right.ir_type == "VariableReference"
    attr.value.right.right.value == "db_password_md5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or broken cryptographic algorithm. (CWE-327)"
    }
}