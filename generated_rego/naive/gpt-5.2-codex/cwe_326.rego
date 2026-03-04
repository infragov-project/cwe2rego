package glitch

import data.glitch_lib

weak_keywords := {
  "des", "3des", "rc2", "rc4", "blowfish", "idea", "xor", "rot", "null", "export", "legacy",
  "sslv2", "sslv3", "ssl2", "ssl3",
  "tls1.0", "tls1.1", "tlsv1.0", "tlsv1.1",
  "md5", "md4", "sha1", "sha-1",
  "ecb", "no_padding", "nopadding", "low"
}

keylen_keywords := {"key_size", "key_length", "key_bits", "key_spec", "keysize", "keylen", "bits", "size"}
rsa_keywords := {"rsa_bits", "rsa_key", "rsa_key_bits", "rsa_key_size", "rsa"}
ecc_keywords := {"ecc_curve", "ec_curve", "elliptic", "ecc", "ecdh", "ecdsa"}
iteration_keywords := {"iterations", "iteration_count", "rounds", "kdf_iterations"}

name_has_keyword(name, keywords) {
    kw := keywords[_]
    glitch_lib.contains(name, kw)
}

weak_keyword_in_name(name) {
    kw := weak_keywords[_]
    glitch_lib.contains(name, kw)
}

weak_method_name_in_node(node) {
    walk(node, [_, n])
    n.ir_type == "MethodCall"
    weak_keyword_in_name(n.method)
}

weak_value(node) {
    glitch_lib.traverse(node, weak_keywords)
} 
weak_value(node) {
    weak_method_name_in_node(node)
}

value_number(v) = n {
    v.ir_type == "Integer"
    n := v.value
}
value_number(v) = n {
    v.ir_type == "Float"
    n := v.value
}
value_number(v) = n {
    v.ir_type == "String"
    regex.match("^[0-9]+$", v.value)
    n := to_number(v.value)
}
value_number(v) = n {
    v.ir_type == "String"
    not regex.match("^[0-9]+$", v.value)
    nums := regex.find_n("[0-9]+", v.value, 1)
    count(nums) > 0
    n := to_number(nums[0])
}

weak_key_length(kv) {
    n := value_number(kv.value)
    name_has_keyword(kv.name, rsa_keywords)
    n < 2048
}
weak_key_length(kv) {
    n := value_number(kv.value)
    name_has_keyword(kv.name, ecc_keywords)
    n < 224
}
weak_key_length(kv) {
    n := value_number(kv.value)
    name_has_keyword(kv.name, keylen_keywords)
    not name_has_keyword(kv.name, rsa_keywords)
    not name_has_keyword(kv.name, ecc_keywords)
    n < 128
}

weak_iterations(kv) {
    name_has_keyword(kv.name, iteration_keywords)
    n := value_number(kv.value)
    n < 1000
}

weak_encryption_kv(kv) {
    weak_value(kv.value)
}
weak_encryption_kv(kv) {
    weak_keyword_in_name(kv.name)
}
weak_encryption_kv(kv) {
    weak_key_length(kv)
}
weak_encryption_kv(kv) {
    weak_iterations(kv)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    weak_encryption_kv(attr)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption configuration detected - Avoid outdated algorithms, insufficient key sizes, legacy protocols, or insecure modes. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    weak_encryption_kv(var)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption configuration detected - Avoid outdated algorithms, insufficient key sizes, legacy protocols, or insecure modes. (CWE-326)"
    }
}