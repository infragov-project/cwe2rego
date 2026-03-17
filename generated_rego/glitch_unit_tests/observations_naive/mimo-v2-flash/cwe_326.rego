package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "Blowfish", "SHA1", "MD5", "RSA-1024"}
deprecated_protocols := {"TLS1.0", "TLS1.1", "SSLv3", "SSLv2", "ELBSecurityPolicy-2014-01"}
weak_ciphers := {"RC4", "DES", "3DES", "MD5", "SHA1"}
weak_key_sizes := {56, 64, 128, 1024}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    regex.match("(?i)(DES|3DES|RC4|AES-128|Blowfish|SHA1|MD5|RSA-1024)", n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (e.g., DES, RC4, MD5) - Use stronger algorithms like AES-256. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "MethodCall"
    regex.match("(?i)(Digest::MD5|MD5)", n.receiver.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (MD5) - Use stronger algorithms like AES-256. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 56
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (56-bit) - Use modern key lengths (e.g., RSA-2048+). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 64
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (64-bit) - Use modern key lengths (e.g., RSA-2048+). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (128-bit) - Use modern key lengths (e.g., RSA-2048+). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (1024-bit) - Use modern key lengths (e.g., RSA-2048+). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    regex.match("(?i)(TLS1\\.0|TLS1\\.1|SSLv3|SSLv2|ELBSecurityPolicy-2014-01)", n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Deprecated TLS/SSL protocol detected - Use TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "cipher_suites"
    attr.value.ir_type == "Array"
    some i
    elem := attr.value.value[i]
    elem.ir_type == "String"
    regex.match("(?i)(RC4|DES|3DES|MD5|SHA1)", elem.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected (e.g., RC4, DES) - Use stronger ciphers. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "block_cipher_mode"
    attr.value.ir_type == "String"
    attr.value.value == "ECB"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak block cipher mode (ECB) detected - Use CBC or GCM instead. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "initialization_vector"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Static initialization vector detected - Use randomized IVs. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "iv"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Static initialization vector detected - Use randomized IVs. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "nonce"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Static initialization vector detected - Use randomized IVs. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "rotation_period"
    attr.value.ir_type == "String"
    regex.match(`(?i)(365d|1y|365 days|1 year|52 weeks|12 months|365)`, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key rotation period detected - Use shorter rotation periods (e.g., 90 days). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "FunctionCall"
    n.name == "filter|hash"
    count(n.args) > 1
    n.args[1].ir_type == "String"
    n.args[1].value == "md5"
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (MD5 hash function) - Use stronger algorithms like SHA-256. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "shell"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "shell"
    glitch_lib.traverse(attr.value, "(?i)(md5)")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm (MD5) detected in shell command. (CWE-326)"
    }
}