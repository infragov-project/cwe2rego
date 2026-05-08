package glitch

import data.glitch_lib

weak_crypto_pattern := "(?i)\\b(DES|3DES|TripleDES|RC4|MD5|SHA1?|SHA-1|ECB|TEA|ROT25|XOR|Blowfish|Vigenère|TLSv1\\.0|TLSv1\\.1)\\b"
security_attributes := {"algorithm", "cipher", "hash", "encryption", "ssl", "tls", "signature", "key", "password", "secret", "token"}
security_functions := {"hash", "encrypt", "decrypt", "sign", "verify", "md5", "sha1", "filter|hash", "filter|md5", "filter|sha1"}
cryptographic_commands := {"openssl", "gpg", "ssh-keygen"}

is_security_context(node) {
    node.ir_type == "Attribute"
    security_attributes[node.name]
} else {
    node.ir_type == "Variable"
    security_attributes[node.name]
} else {
    node.ir_type == "FunctionCall"
    regex.match("(?i)hash|encrypt|decrypt|sign|verify", node.name)
}

contains_crypto_command(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)openssl|gpg|ssh-keygen", n.value)
}

find_weak_crypto_nodes(value) = nodes {
    nodes := {n |
        walk(value, [_, n])
        n.ir_type == "String"
        regex.match(weak_crypto_pattern, n.value)
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_security_context(attr)
    weak_nodes := find_weak_crypto_nodes(attr.value)
    count(weak_nodes) > 0
    node := weak_nodes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak algorithms such as DES, MD5, or outdated protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_security_context(var)
    weak_nodes := find_weak_crypto_nodes(var.value)
    count(weak_nodes) > 0
    node := weak_nodes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak algorithms such as DES, MD5, or outdated protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_security_context(node)
    weak_nodes := {wn |
        walk(node.args, [_, arg])
        wn := find_weak_crypto_nodes(arg)
    }
    count(weak_nodes) > 0
    wn := weak_nodes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": wn,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak algorithms such as DES, MD5, or outdated protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in {"shell", "command"}
    contains_crypto_command(attr.value)
    weak_nodes := find_weak_crypto_nodes(attr.value)
    count(weak_nodes) > 0
    node := weak_nodes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak algorithms such as DES, MD5, or outdated protocols. (CWE-327)"
    }
}