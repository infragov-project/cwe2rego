package glitch

import data.glitch_lib

# Define the set of broken or risky cryptographic algorithms
broken_algorithms := {"DES", "3DES", "RC2", "RC4", "ARC4", "Blowfish", "AES-ECB", "MD2", "MD4", "MD5", "SHA-1", "ROT-13", "Base64", "XOR", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "SSHv1"}

# Define the attribute names that might contain algorithm values
algorithm_attributes := {"algorithm", "encryption", "cipher", "hash_type", "tls_version", "ssl_version", "min_protocol", "protocol_version"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check if the attribute name is one of the algorithm-related attributes
    attr.name in algorithm_attributes

    # Check if the attribute value is a string matching a broken algorithm
    attr.value.ir_type == "String"
    algorithm := attr.value.value
    algorithm in broken_algorithms

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated or insecure cryptographic algorithms. (CWE-327)"
    }
}