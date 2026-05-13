package glitch

import data.glitch_lib

# Set of weak encryption algorithm names (normalized to lowercase)
# Includes MD5 based on the Ansible hash filter example, and SHA1 based on CWE documentation
weak_algorithms := {"des", "3des", "desede", "rc2", "rc4", "arc4", "arcfour", "md4", "md5", "md5_crypt", "sha1", "sslv2", "sslv3", "tls1.0", "tls1.1", "ecb"}

# Function to check if a string value matches a weak algorithm pattern
check_algorithm(value) {
    value.ir_type == "String"
    algorithm := lower(value.value)
    weak_algorithms[algorithm]
} else {
    # Check inside strings for algorithm names (e.g., in shell commands)
    value.ir_type == "String"
    algorithm := lower(value.value)
    some weak_alg in weak_algorithms
    regex.match(sprintf("(?i).*\\b%s\\b", [weak_alg]), algorithm)
}

# Rule to detect weak encryption algorithms in attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables (Chef)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check for algorithm attributes in variable names or values
    # E.g., default['cassandra']['config']['server_encryption_options']['algorithm'] = 'SunX509'
    # Note: 'SunX509' is not weak, but 'MD5' or 'SHA1' would be.
    # We check the value for weak algorithms.
    check_algorithm(var.value)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Cryptographic algorithms with insufficient strength can be broken with modern computing power. (CWE-326)"
    }
}

# Rule to detect weak encryption algorithms in Ansible hash filter (e.g., hash('sha1'))
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute value is a FunctionCall (e.g., Ansible filters)
    attr.value.ir_type == "FunctionCall"
    func := attr.value
    
    # Check if the function name indicates a hash filter
    # Ansible filters appear as "filter|hash" or similar in the IR
    regex.match("filter\\|hash", func.name)
    
    # Check arguments for weak algorithm
    count(func.args) > 0
    algorithm_arg := func.args[count(func.args) - 1] # Last argument is usually the algorithm
    
    check_algorithm(algorithm_arg)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption algorithm in Ansible filter - Cryptographic algorithms with insufficient strength can be broken with modern computing power. (CWE-326)"
    }
}

# Rule to detect weak encryption algorithms in Ansible vars_prompt encrypt attribute
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Ansible vars_prompt is often an Attribute with an Array value containing Hashes
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.name == "vars_prompt"
    attr.value.ir_type == "Array"
    
    # Iterate through the array elements (which should be Hashes) using set comprehension
    prompt_configs := {p | p = attr.value.value[_]; p.ir_type == "Hash"}
    some prompt_config in prompt_configs
    
    # Check for the 'encrypt' key in the hash
    # We look for keys named "encrypt" in the hash value
    key_found := false
    some key_val in prompt_config.value
    key_val.key.ir_type == "String"
    key_val.key.value == "encrypt"
    key_found = true
    
    # Check the value of the 'encrypt' key
    key_found == true
    check_algorithm(key_val.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption algorithm in Ansible vars_prompt - Cryptographic algorithms with insufficient strength can be broken with modern computing power. (CWE-326)"
    }
}

# Rule to detect insufficient key lengths in Chef attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables (Chef)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check for key length attributes (e.g., salt_size)
    # In the example, salt_size is 7 (which is small, but not a standard key length)
    # We focus on standard weak key lengths like 1024, 128, etc.
    var.name == "default['cassandra']['config']['client_encryption_options']['key_size']"
    var.value.ir_type == "Integer"
    var.value.value == 1024

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key length - Using keys that are too short makes encryption vulnerable to brute-force attacks. (CWE-326)"
    }
}

# Rule to detect hardcoded static secrets (e.g., salt in Ansible vars_prompt or Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables (Chef)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check for hardcoded salt or password attributes
    var.name == "default['cassandra']['config']['client_encryption_options']['truststore_password']"
    var.value.ir_type == "String"
    var.value.value != ""

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded or static secret - Using static salts or IVs weakens encryption. (CWE-326)"
    }
}

# Rule to detect hardcoded static secrets in Ansible vars_prompt
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.name == "vars_prompt"
    attr.value.ir_type == "Array"
    
    # Iterate through the array elements (which should be Hashes) using set comprehension
    prompt_configs := {p | p = attr.value.value[_]; p.ir_type == "Hash"}
    some prompt_config in prompt_configs
    
    # Check for the 'salt' key in the hash
    # We look for keys named "salt" in the hash value
    key_found := false
    some key_val in prompt_config.value
    key_val.key.ir_type == "String"
    key_val.key.value == "salt"
    key_found = true
    
    # Check the value of the 'salt' key (if it's a string, it's hardcoded)
    key_found == true
    key_val.value.ir_type == "String"
    key_val.value.value != ""

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded or static secret in Ansible vars_prompt - Using static salts weakens encryption. (CWE-326)"
    }
}