package glitch

import data.glitch_lib

# Weak cryptographic algorithms and protocols (CWE-327)
weak_crypto_indicators := {
    "DES", "3DES", "RC4", "MD5", "SHA1", "ECB",
    "SSLv2", "SSLv3", "TLS_1_0", "TLS_1_1",
    "NULL", "EXPORT", "anon", "md5_crypt"
}

# Helper: Check if a string contains a weak indicator (case-insensitive)
is_weak_crypto_value(str_val) {
    some indicator
    weak_crypto_indicators[indicator]
    regex.match(sprintf("(?i).*%s.*", [indicator]), str_val)
}

# Helper: Check if a node is a String with a weak crypto value
check_string_node(node) {
    node.ir_type == "String"
    is_weak_crypto_value(node.value)
}

# Helper: Check FunctionCall arguments (e.g., Ansible filters)
check_function_call(node) {
    node.ir_type == "FunctionCall"
    some arg
    arg = node.args[_]
    check_string_node(arg)
}

# Helper: Check Array elements (e.g., cipher suites list)
check_array_node(node) {
    node.ir_type == "Array"
    some elem
    elem = node.value[_]
    check_string_node(elem)
}

# Helper: Recursively check a value for weak crypto indicators
# Uses a safe bounded walk to avoid infinite recursion on deep structures
check_value(node) {
    walk(node, [path, n])
    n.ir_type == "String"
    is_weak_crypto_value(n.value)
}

# Helper: Check the key name for crypto-related keywords
# This helps reduce false positives by checking if the config is crypto-related
is_crypto_related_key(key) {
    crypto_keywords := {"algorithm", "encryption", "cipher", "hash", "protocol", "ssl", "tls", "md5", "sha"}
    some k
    crypto_keywords[k]
    regex.match(sprintf("(?i).*%s.*", [k]), key)
}

# Rule 1: Detect weak crypto in Attributes (Ansible module params, Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute name is crypto-related (to reduce false positives)
    is_crypto_related_key(attr.name)
    
    # Check if the attribute value contains a weak indicator
    check_value(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

# Rule 2: Detect weak crypto in Variables (Ansible vars, Chef variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable name is crypto-related (to reduce false positives)
    is_crypto_related_key(var.name)
    
    # Check if the variable value contains a weak indicator
    check_value(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

# Rule 3: Detect weak crypto in FunctionCall arguments (Ansible filters)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute name is crypto-related
    is_crypto_related_key(attr.name)
    
    # Check FunctionCall within the attribute value
    check_function_call(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

# Rule 4: Detect weak crypto in Array values (e.g., cipher suites lists)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute name is crypto-related
    is_crypto_related_key(attr.name)
    
    # Check Array within the attribute value
    check_array_node(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}