package glitch

import data.glitch_lib

weak_algorithm_pattern := "(?i)\\b(des|3des|rc4|md5|sha1|sha-1|aes-128|ecb|rsa_1024|dh_1024)\\b"
weak_protocol_pattern := "(?i)\\b(ssl[vv]2|ssl[vv]3|tls[ _]1\\.0|tls[ _]1\\.1|sshv1|ftp|telnet)\\b"
weak_hash_pattern := "(?i)\\b(md5|sha1|sha-1|md4)\\b"
hardcoded_secret_names := {"secret", "password", "key", "token", "secret_key", "api_key", "secret_password", "auth_token"}
key_length_names := {"key_length", "key_size"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(weak_algorithm_pattern, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(weak_protocol_pattern, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak cryptographic protocol (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(weak_hash_pattern, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak hash algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    hardcoded_secret_names[attr.name]
    attr.value.ir_type == "String"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded secret in plaintext (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    hardcoded_secret_names[var.name]
    var.value.ir_type == "String"
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded secret in plaintext (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_length_names[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key length (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_hash_pattern, node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak hash algorithm in function call (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "MethodCall"
    regex.match(weak_hash_pattern, node.method)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a weak hash algorithm in method call (CWE-327)"
    }
}