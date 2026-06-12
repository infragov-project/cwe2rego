package glitch

import data.glitch_lib

weak_algorithms = {"DES", "3DES", "RC4", "SHA1", "AES128", "blowfish", "rc4-md5", "md5_crypt", "md5"}
insufficient_key_lengths = {128, 1024, 160}
insufficient_key_length_attrs = {"key_size", "key_length", "bits", "min_key_length"}
weak_protocols = {"TLS-1-0", "TLS-1-1", "SSL-2-0", "SSL-3.0"}
weak_protocol_attrs = {"protocol_version", "min_tls_version", "ssl_version", "tls_security_policy"}
weak_cipher_suites = {"DES-CBC3-SHA", "RC4-SHA", "AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"}
misconfigured_service_attrs = {"encryption_enabled", "sse_algorithm"}

is_weak_algorithm(str_value) {
    lower_str := lower(str_value)
    algorithm := weak_algorithms[_]
    lower_str == lower(algorithm)
}

contains_weak_substring(str_value) {
    lower_str := lower(str_value)
    algorithm := weak_algorithms[_]
    contains(lower_str, lower(algorithm))
}

check_function_call_weak_algorithm(func_call) {
    arg := func_call.args[_]
    arg.ir_type == "String"
    is_weak_algorithm(arg.value)
} else {
    is_weak_algorithm(func_call.name)
}

contains_weak_cipher_suite(str_value) {
    cipher := weak_cipher_suites[_]
    contains(str_value, cipher)
}

contains_weak_attr_name(name, attrs) {
    attrs[name]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "shell"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "shell"
    attr.value.ir_type == "String"
    contains_weak_substring(attr.value.value)
    not contains(attr.value.value, "aes-256")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption algorithm in shell command - Avoid using weak encryption algorithms in shell commands. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    is_weak_algorithm(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using weak encryption algorithms such as DES, 3DES, RC4, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "FunctionCall"
    check_function_call_weak_algorithm(n)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using weak encryption algorithms such as DES, 3DES, RC4, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    contains_weak_attr_name(n.name, insufficient_key_length_attrs)
    n.value.ir_type == "Integer"
    insufficient_key_lengths[n.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key length - Use of insufficient key length for encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    contains_weak_attr_name(n.name, insufficient_key_length_attrs)
    n.value.ir_type == "Integer"
    insufficient_key_lengths[n.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key length - Use of insufficient key length for encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    contains_weak_attr_name(n.name, weak_protocol_attrs)
    n.value.ir_type == "String"
    weak_protocols[n.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of outdated protocol version - Avoid using outdated protocols such as TLS 1.0, TLS 1.1, SSL 2.0/3.0. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    contains_weak_attr_name(n.name, weak_protocol_attrs)
    n.value.ir_type == "String"
    weak_protocols[n.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of outdated protocol version - Avoid using outdated protocols such as TLS 1.0, TLS 1.1, SSL 2.0/3.0. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    n.name == "key_rotation"
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Disabled key rotation - Key rotation should be enabled to ensure regular key updates. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    n.name == "key_rotation"
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Disabled key rotation - Key rotation should be enabled to ensure regular key updates. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    n.name == "hardcoded_key"
    n.value.ir_type == "String"
    glitch_lib.traverse_var(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Hardcoded cryptographic key - Avoid hardcoding cryptographic keys in the code. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    n.name == "hardcoded_key"
    n.value.ir_type == "String"
    glitch_lib.traverse_var(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Hardcoded cryptographic key - Avoid hardcoding cryptographic keys in the code. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    n.name == "encryption_enabled"
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption disabled - Encryption should be enabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    n.name == "encryption_enabled"
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption disabled - Encryption should be enabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    n.name == "sse_algorithm"
    n.value.ir_type == "String"
    is_weak_algorithm(n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak SSE algorithm - Use of weak SSE algorithm when stronger algorithm is required. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    n.name == "sse_algorithm"
    n.value.ir_type == "String"
    is_weak_algorithm(n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak SSE algorithm - Use of weak SSE algorithm when stronger algorithm is required. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    contains(n.name, "cipher_suites")
    n.value.ir_type == "String"
    contains_weak_cipher_suite(n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak cipher suite - Avoid using weak cipher suites in encryption configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    contains(n.name, "cipher_suites")
    n.value.ir_type == "String"
    contains_weak_cipher_suite(n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak cipher suite - Avoid using weak cipher suites in encryption configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    lower_name := lower(n.name)
    contains(lower_name, "password")
    n.value.ir_type == "Access"
    n.value.right.ir_type == "String"
    contains_weak_substring(n.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak hashing algorithm for password - Avoid using weak hashing algorithms like MD5 for passwords. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    lower_name := lower(n.name)
    contains(lower_name, "password")
    n.value.ir_type == "Access"
    n.value.right.ir_type == "String"
    contains_weak_substring(n.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak hashing algorithm for password - Avoid using weak hashing algorithms like MD5 for passwords. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    lower_name := lower(n.name)
    contains(lower_name, "password")
    n.value.ir_type == "String"
    contains_weak_substring(n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak hashing algorithm for password - Avoid using weak hashing algorithms like MD5 for passwords. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    lower_name := lower(n.name)
    contains(lower_name, "password")
    n.value.ir_type == "String"
    contains_weak_substring(n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak hashing algorithm for password - Avoid using weak hashing algorithms like MD5 for passwords. (CWE-326)"
    }
}