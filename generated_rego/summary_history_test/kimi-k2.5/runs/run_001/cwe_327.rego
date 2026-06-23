package glitch

import data.glitch_lib

weak_algorithms = {"DES", "3DES", "RC2", "RC4", "MD5", "SHA1", "SHA-1", "ECB", "CBC"}
weak_tls_versions = {"TLSv1.0", "TLSv1.1", "SSLv3", "TLS1.0", "TLS1.1"}
encryption_keywords = {"encryption", "encrypted", "encrypt", "kms_key_id", "sse_algorithm", "cipher", "ciphers", "cipher_suites", "tls_version", "ssl_policy", "min_tls_version", "ssl_mode", "hash_algorithm", "digest", "key_exchange", "hash", "checksum", "auth_method", "password", "algorithm"}

disabled_flags = {"encryption_enabled", "encrypted", "sse_enabled", "tls_enabled", "ssl_enabled", "encryption"}
inssl_flags = {"tls_disabled", "ssl_disabled", "insecure_ssl", "skip_ssl", "verify_ssl", "http_protocol", "ssl"}

is_weak_algorithm_exact(val) {
    alg := weak_algorithms[_]
    lower(trim_space(val)) == lower(alg)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)(^|[^a-z])md5([^a-z]|$)", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)sha[-_]?1", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)(^|[^a-z])des([^a-z]|$)", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)3des", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)rc2", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)rc4", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)ecb", val)
}

is_weak_algorithm_regex(val) {
    regex.match("(?i)cbc", val)
}

is_weak_algorithm(val) {
    is_weak_algorithm_exact(val)
} else {
    is_weak_algorithm_regex(val)
}

is_weak_tls_str(val) {
    ver := weak_tls_versions[_]
    contains(val, ver)
}

encryption_related(name) {
    kw := encryption_keywords[_]
    contains(lower(name), lower(kw))
}

is_encryption_disabled(attr) {
    attr.name == disabled_flags[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

is_insecure_ssl(attr) {
    attr.name == inssl_flags[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

all_leaves(root) = leaves {
    leaves = {n |
        walk(root, [path, n])
        n.ir_type == "String"
    }
}

func_name_contains_weak(name) {
    lower(name) == "md5"
}

func_name_contains_weak(name) {
    regex.match("(?i)sha[-_]?1", name)
}

func_name_contains_weak(name) {
    regex.match("(?i)(^|[^a-z])des([^a-z]|$)", name)
}

func_name_contains_weak(name) {
    regex.match("(?i)3des", name)
}

func_name_contains_weak(name) {
    regex.match("(?i)rc2", name)
}

func_name_contains_weak(name) {
    regex.match("(?i)rc4", name)
}

func_name_contains_weak(name) {
    regex.match("(?i)hash.*md5", name)
}

func_name_contains_weak(name) {
    regex.match("(?i)hash.*sha[-_]?1", name)
}

any_arg_contains_weak(args) {
    arg := args[_]
    arg.ir_type == "String"
    is_weak_algorithm(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    func_name_contains_weak(node.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call using weak cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    any_arg_contains_weak(node.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm argument. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    func_name_contains_weak(node.name)
    any_arg_contains_weak(node.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm argument. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    attr.value.ir_type == "FunctionCall"
    func_name_contains_weak(attr.value.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call using weak cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attr := glitch_lib.all_attributes(node)[_]
    attr.value.ir_type == "FunctionCall"
    func_name_contains_weak(attr.value.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call using weak cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := glitch_lib.all_variables(parent)[_]
    var.value.ir_type == "FunctionCall"
    func_name_contains_weak(var.value.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call using weak cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    attr.value.ir_type == "FunctionCall"
    any_arg_contains_weak(attr.value.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm argument. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    any_arg_contains_weak(attr.value.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm argument. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := glitch_lib.all_variables(parent)[_]
    var.value.ir_type == "FunctionCall"
    any_arg_contains_weak(var.value.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm argument. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    encryption_related(attr.name)
    attr.value.ir_type == "String"
    is_weak_algorithm(attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_related(attr.name)
    attr.value.ir_type == "String"
    is_weak_algorithm(attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := glitch_lib.all_variables(parent)[_]
    encryption_related(var.name)
    var.value.ir_type == "String"
    is_weak_algorithm(var.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    encryption_related(node.name)
    node.value.ir_type == "String"
    is_weak_algorithm(node.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm in variable assignment. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    encryption_related(attr.name)
    leaf := all_leaves(attr.value)[_]
    is_weak_algorithm(leaf.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm detected in complex attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_related(attr.name)
    leaf := all_leaves(attr.value)[_]
    is_weak_algorithm(leaf.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm detected in complex attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := glitch_lib.all_variables(parent)[_]
    encryption_related(var.name)
    leaf := all_leaves(var.value)[_]
    is_weak_algorithm(leaf.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm detected in complex variable assignment. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    encryption_related(attr.name)
    attr.value.ir_type == "String"
    is_weak_tls_str(attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak TLS version detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_related(attr.name)
    attr.value.ir_type == "String"
    is_weak_tls_str(attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak TLS version detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    is_encryption_disabled(attr)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Encryption should not be disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    is_insecure_ssl(attr)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Insecure SSL/TLS configuration detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    item := node.value[_]
    item.key.ir_type == "String"
    encryption_related(item.key.value)
    item.value.ir_type == "String"
    is_weak_algorithm(item.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": item,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm in hash structure. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "String"
    is_weak_algorithm(elem.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm in array element. (CWE-327)"
    }
}