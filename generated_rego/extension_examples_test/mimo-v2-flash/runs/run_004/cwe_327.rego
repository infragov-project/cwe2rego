package glitch

import data.glitch_lib
import future.keywords.in

weak_string_patterns := {"md5", "sha1", "des", "3des", "rc4", "aes-128", "rsa-1024", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "custom", "proprietary"}

crypto_keywords := {"algorithm", "hash", "cipher", "protocol", "key", "encrypt", "decrypt", "ssl", "tls", "md5", "sha1", "des", "3des", "rc4", "rsa", "digest", "signature", "salt", "crypt"}

is_weak_value(value) {
    is_string(value)
    some pattern in weak_string_patterns
    regex.match(sprintf("(?i).*%s.*", [pattern]), value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    some keyword in crypto_keywords
    contains(attr.name, keyword)
    walk(attr.value, [path, node])
    node.ir_type == "String"
    is_weak_value(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or setting. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    some keyword in crypto_keywords
    contains(var.name, keyword)
    walk(var.value, [path, node])
    node.ir_type == "String"
    is_weak_value(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or setting. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    contains(attr.name, "key_length")
    walk(attr.value, [path, node])
    node.ir_type == "Integer"
    node.value == 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak key length. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    contains(var.name, "key_length")
    walk(var.value, [path, node])
    node.ir_type == "Integer"
    node.value == 1024
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak key length. (CWE-327)"
    }
}