package glitch

import data.glitch_lib

# CWE-326: Use of weak cryptographic algorithms or insufficient key lengths

# Define weak cryptographic algorithms and patterns as a set
weak_crypto_values := {
    "des", "3des", "tripledes", "rc2", "rc4", "md5", "sha1", "sha-1",
    "blowfish", "ecb", "pkcs5padding", "pkcs7padding", "nopadding", "zeropadding",
    "secp112r1", "secp128r1", "rsa1024", "dsa1024", "md5_crypt", "sunx509",
    "tls_rsa_with_aes_128_cbc_sha", "tls_rsa_with_aes_256_cbc_sha"
}

# Check for weak algorithm strings in a value node
is_weak_crypto_value(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    some weak_val
    weak_crypto_values[weak_val]
    contains(lower_val, weak_val)
}

is_weak_crypto_value(val) {
    val.ir_type == "Access"
    is_weak_crypto_value(val.right)
}

is_weak_crypto_value(val) {
    val.ir_type == "FunctionCall"
    some arg
    val.args[arg]
    is_weak_crypto_value(val.args[arg])
}

# Check for insufficient key sizes (RSA/DSA < 2048, symmetric < 128)
is_weak_key_size(val) {
    val.ir_type == "Integer"
    val.value < 2048
}

is_weak_key_size(val) {
    val.ir_type == "String"
    regex.match("^(1024|512)$", val.value)
}

# Check for weak ciphersuites
is_weak_ciphersuite(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    contains(lower_val, "tls_rsa_with_aes_128")
}

is_weak_ciphersuite(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    contains(lower_val, "_sha$")
}

# Gather all attributes from the parent node
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]

    # Check if attribute name is cryptographically relevant
    crypto_attr_names := {"algorithm", "cipher", "encryption", "hash", "mode", "key_size", "encrypt", "cipher_suites"}
    crypto_attr_names[attr.name]

    # Check for weak algorithms or key sizes
    is_weak_crypto_value(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or hash. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]

    crypto_attr_names := {"algorithm", "cipher", "encryption", "hash", "mode", "key_size", "encrypt"}
    crypto_attr_names[attr.name]

    is_weak_key_size(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insufficient key size for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    lower_node := lower(node.value)
    contains(lower_node, "md5_crypt")

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak MD5 crypt algorithm. (CWE-326)"
    }
}