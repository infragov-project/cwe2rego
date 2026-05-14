package glitch

import data.glitch_lib

# Define insecure encryption algorithms and weak configurations
insecure_algorithms := {"md5", "sha1", "des", "3des", "rc4", "ssl_v2", "ssl_v3", "tls_v1.0", "tls_v1.1"}
weak_cipher_suites := {"aes_128", "aes128", "tls_rsa_with_aes_128"}
insecure_auth_methods := {"md5", "des", "crypt"}

# Check for weak encryption values in string nodes
check_weak_encryption(value) {
    value.ir_type == "String"
    algorithm := lower(value.value)
    weak := insecure_algorithms[_]
    contains(algorithm, weak)
}

# Check for weak cipher suites in strings containing multiple values
check_weak_cipher_suite(value) {
    value.ir_type == "String"
    algorithm := lower(value.value)
    weak := weak_cipher_suites[_]
    contains(algorithm, weak)
}

# Check for insecure authentication methods
check_insecure_auth(value) {
    value.ir_type == "String"
    method := lower(value.value)
    insecure := insecure_auth_methods[_]
    method == insecure
}

# Rule 1: Detect weak encryption in FunctionCall arguments (Ansible case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    count(node.args) > 0
    arg := node.args[_]
    check_weak_encryption(arg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": arg,
        "path": parent.path,
        "description": sprintf("Use of weak encryption algorithm '%s' in function call. (CWE-326)", [arg.value])
    }
}

# Rule 2: Detect weak encryption in Attribute values (Chef and Puppet cases)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    check_weak_encryption(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of weak encryption algorithm '%s' in attribute. (CWE-326)", [node.value.value])
    }
}

# Rule 3: Detect weak cipher suites in Variable values (Chef case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    check_weak_cipher_suite(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of weak cipher suite '%s' in variable. (CWE-326)", [node.value.value])
    }
}

# Rule 4: Detect insecure authentication methods (Puppet case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "auth_method"
    node.value.ir_type == "String"
    check_insecure_auth(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of insecure authentication method '%s'. (CWE-326)", [node.value.value])
    }
}

# Rule 5: Generic detection of weak encryption in any String node
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    check_weak_encryption(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of weak encryption algorithm '%s'. (CWE-326)", [node.value])
    }
}