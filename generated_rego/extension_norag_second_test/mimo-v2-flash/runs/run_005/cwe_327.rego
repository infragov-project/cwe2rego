package glitch

import data.glitch_lib

weak_encryption_algorithms := {"DES", "3DES", "RC4", "RC2", "Blowfish", "AES-ECB", "RSA-1024", "DSA-1024"}
weak_hashing_algorithms := {"MD4", "MD5", "SHA1", "LM", "NTLM"}
insecure_protocols := {"SSLv2", "SSLv3", "TLS_1_0", "TLS_1_1", "SSH_1"}
algorithm_attributes := {"algorithm", "cipher", "encryption_algorithm", "encryption_type", "hashing_algorithm", "password_hash", "signature_algorithm", "checksum", "protocol_version", "min_tls_version", "ssl_policy", "cipher_suites"}
secret_name_patterns := {"password", "secret", "key", "token", "api", "client"}
lack_encryption_patterns := {"storage_encryption", "encrypt_data", "encrypted", "enable_encryption", "encryption_enabled"}
hardware_ip_attributes := {"crypto_ip_name", "bitstream_encryption"}
weak_hardware_ips := {"sha1_core", "des_accelerator"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "String"
    some weak_algo
    weak_encryption_algorithms[weak_algo]
    glitch_lib.contains(n.value, weak_algo)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "String"
    some weak_hash
    weak_hashing_algorithms[weak_hash]
    glitch_lib.contains(n.value, weak_hash)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak hashing algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "String"
    some proto
    insecure_protocols[proto]
    glitch_lib.contains(n.value, proto)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of insecure protocol version (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some pattern
    algorithm_attributes[pattern]
    glitch_lib.contains(attr.name, pattern)
    walk(attr.value, [path, n])
    n.ir_type == "String"
    some weak_algo
    weak_encryption_algorithms[weak_algo]
    glitch_lib.contains(n.value, weak_algo)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some pattern
    algorithm_attributes[pattern]
    glitch_lib.contains(attr.name, pattern)
    walk(attr.value, [path, n])
    n.ir_type == "String"
    some weak_hash
    weak_hashing_algorithms[weak_hash]
    glitch_lib.contains(n.value, weak_hash)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak hashing algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some pattern
    algorithm_attributes[pattern]
    glitch_lib.contains(attr.name, pattern)
    walk(attr.value, [path, n])
    n.ir_type == "String"
    some proto
    insecure_protocols[proto]
    glitch_lib.contains(n.value, proto)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure protocol version (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some pattern
    secret_name_patterns[pattern]
    glitch_lib.contains(attr.name, pattern)
    attr.value.ir_type == "String"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded cryptographic secret (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    some pattern
    secret_name_patterns[pattern]
    glitch_lib.contains(var.name, pattern)
    var.value.ir_type == "String"
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded cryptographic secret (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some pattern
    lack_encryption_patterns[pattern]
    glitch_lib.contains(attr.name, pattern)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Lack of encryption enabled (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some pattern
    lack_encryption_patterns[pattern]
    glitch_lib.contains(attr.name, pattern)
    attr.value.ir_type == "Null"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Lack of encryption enabled (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    some ip_attr
    hardware_ip_attributes[ip_attr]
    attr.name == ip_attr
    walk(attr.value, [path, n])
    n.ir_type == "String"
    some weak_ip
    weak_hardware_ips[weak_ip]
    glitch_lib.contains(n.value, weak_ip)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak hardware IP for cryptography (CWE-327)"
    }
}