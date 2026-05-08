package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "tripledes", "desede", "rc4", "arc4", "arcfour", "blowfish", "rc2", "idea", "md5", "sha1", "sha-1", "sha224", "sha-224", "hmac-md5", "hmac-sha1", "hmac-sha-1", "sslv2", "sslv3", "tls1.0", "tls 1.0", "tls1.1", "tls 1.1", "md5_crypt", "otp", "xor", "base64"}

weak_sizes := {"512", "1024", "64", "128"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "filter|hash"
    weak_hash := {"sha1", "md5", "sha-1", "sha224", "sha-224"}
    some arg
    node.args[_] == arg
    arg.ir_type == "String"
    lower_arg := lower(arg.value)
    weak_hash[_] == lower_arg
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak hashing algorithm (e.g., SHA-1, MD5). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    encryption_keywords := {"algorithm", "cipher", "encryption", "hash", "signature", "protocol"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", encryption_keywords)]), attr.name)
    attr.value.ir_type == "String"
    lower_val := lower(attr.value.value)
    weak_algorithms[_] == lower_val
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or outdated cryptographic algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    key_size_keywords := {"key_length", "key_size", "bits", "size", "key_algorithm", "key_spec", "salt_size"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", key_size_keywords)]), attr.name)
    attr.value.ir_type == "String"
    lower_val := lower(attr.value.value)
    weak_sizes[_] == lower_val
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or inadequate key size for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    key_size_keywords := {"key_length", "key_size", "bits", "size", "salt_size"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", key_size_keywords)]), attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 512
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or inadequate key size for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    key_size_keywords := {"key_length", "key_size", "bits", "size", "salt_size"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", key_size_keywords)]), attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or inadequate key size for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    key_size_keywords := {"key_length", "key_size", "bits", "size", "salt_size"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", key_size_keywords)]), attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 64
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or inadequate key size for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    key_size_keywords := {"key_length", "key_size", "bits", "size", "salt_size"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", key_size_keywords)]), attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or inadequate key size for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"
    attr_name_lower := lower(attr.name)
    randomness_keywords := {"salt", "iv", "initialization_vector", "nonce", "salt_size", "random"}
    regex.match(sprintf("(?i).*%s.*", [concat("|", randomness_keywords)]), attr.name)
    attr.value.ir_type == "String"
    lower_val := lower(attr.value.value)
    lower_val == "static" or lower_val == "fixed" or lower_val == "null"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of static or predictable initialization vectors or salts. (CWE-326)"
    }
}