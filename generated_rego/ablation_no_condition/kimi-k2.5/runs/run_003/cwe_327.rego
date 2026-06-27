package glitch

import data.glitch_lib
import future.keywords.in

broken_crypto_algorithms := {
    "des", "3des", "tripledes", "md5", "md5_crypt", "md4", "sha0", "sha1",
    "rc4", "rc2", "blowfish", "cast5", "tea", "xtea",
    "rot13", "rot5", "rot25", "xor", "ecb", "rc5", "sha-1"
}

crypto_attr_names := {
    "algorithm", "encryption", "cipher", "hash", "digest",
    "crypto", "cryptography", "signature", "sign",
    "checksum", "mac", "hmac", "kdf", "key_derivation",
    "encrypt", "mode", "enc"
}

security_sensitive_names := {
    "password", "secret", "key", "token", "credential", "cert",
    "private", "auth", "login", "passwd"
}

contains_broken_crypto(str) {
    lower_str := lower(str)
    some algo in broken_crypto_algorithms
    regex.match(sprintf(".*%s.*", [algo]), lower_str)
}

is_crypto_attribute(name) {
    lower_name := lower(name)
    some attr in crypto_attr_names
    lower_name == attr
} else {
    lower_name := lower(name)
    some attr in crypto_attr_names
    contains(lower_name, attr)
}

is_security_sensitive(name) {
    lower_name := lower(name)
    some sensitive in security_sensitive_names
    lower_name == sensitive
} else {
    lower_name := lower(name)
    some sensitive in security_sensitive_names
    startswith(lower_name, sprintf("%s_", [sensitive]))
} else {
    lower_name := lower(name)
    some sensitive in security_sensitive_names
    endswith(lower_name, sprintf("_%s", [sensitive]))
} else {
    lower_name := lower(name)
    some sensitive in security_sensitive_names
    contains(lower_name, sensitive)
}

is_cipher_suite_context(name) {
    lower_name := lower(name)
    contains(lower_name, "cipher_suite")
}

string_contains_weak_hash(str) {
    contains(str, "_SHA")
    not contains(str, "_SHA256")
    not contains(str, "_SHA384")
}

is_weak_cipher_suite(value) {
    string_contains_weak_hash(value)
}

check_string_for_crypto(s) {
    contains_broken_crypto(s)
}

check_local_node_for_crypto(node) {
    node.ir_type == "String"
    check_string_for_crypto(node.value)
} else {
    node.ir_type == "VariableReference"
    check_string_for_crypto(node.value)
} else {
    node.ir_type == "FunctionCall"
    contains_broken_crypto(node.name)
} else {
    node.ir_type == "MethodCall"
    contains_broken_crypto(node.method)
}

check_hash_entry_for_crypto(entry) {
    entry.key.ir_type == "String"
    entry.value.ir_type == "String"
    is_crypto_attribute(entry.key.value)
    check_string_for_crypto(entry.value.value)
} else {
    entry.key.ir_type == "String"
    entry.value.ir_type == "String"
    is_security_sensitive(entry.key.value)
    check_string_for_crypto(entry.value.value)
}

any_child_contains_broken_crypto(node) {
    [_, child] := walk(node)
    check_local_node_for_crypto(child)
}

any_array_elem_contains_broken_crypto(arr) {
    some elem in arr.value
    check_local_node_for_crypto(elem)
} else {
    some elem in arr.value
    elem.ir_type == "Hash"
    some entry in elem.value
    check_hash_entry_for_crypto(entry)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_crypto_attribute(node.name)
    check_local_node_for_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_crypto_attribute(node.name)
    any_child_contains_broken_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_security_sensitive(node.name)
    lower(node.name) != "description"
    check_local_node_for_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_security_sensitive(node.name)
    lower(node.name) != "description"
    any_child_contains_broken_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    contains_broken_crypto(node.name)
    lower(node.name) != "description"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_cipher_suite_context(node.name)
    node.value.ir_type == "String"
    is_weak_cipher_suite(node.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    is_security_sensitive(node.name)
    check_local_node_for_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    is_security_sensitive(node.name)
    any_child_contains_broken_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    is_cipher_suite_context(node.name)
    node.value.ir_type == "String"
    is_weak_cipher_suite(node.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    contains_broken_crypto(node.name)
    not startswith(lower(node.name), "openssl")
    not contains(lower(node.name), "aes-256")
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    some arg in node.args
    check_local_node_for_crypto(arg)
    not startswith(lower(node.name), "openssl")
    not contains(lower(node.name), "aes-256")
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    contains_broken_crypto(node.method)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "KeyValue"
    check_hash_entry_for_crypto(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Access"
    node.right.ir_type == "String"
    check_string_for_crypto(node.right.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Array"
    any_array_elem_contains_broken_crypto(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using broken or weak cryptographic algorithms. (CWE-327)"
    }
}