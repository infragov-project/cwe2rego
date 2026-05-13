package glitch

import data.glitch_lib

weak_algorithms = {"MD4", "MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4", "BLOWFISH", "TWOFISH", "DSA", "DH"}
weak_protocols = {"TLS 1.0", "TLS 1.1", "SSL", "SSLv3", "SSHv1"}
weak_modes = {"ECB", "CBC"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    glitch_lib.traverse(attr.value, weak_algorithms)
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
    glitch_lib.traverse(attr.value, weak_protocols)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic protocol (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    glitch_lib.traverse(attr.value, weak_modes)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic mode (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    (attr.name == "key_size" or attr.name == "key_length")
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic key size (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    (attr.name == "user_data" or attr.name == "startup_script" or attr.name == "custom_data")
    glitch_lib.traverse(attr.value, {"openssl.*-md5", "openssl.*-des", "crypt\\("})
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken cryptographic algorithm in user data (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    glitch_lib.traverse(var.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    glitch_lib.traverse(var.value, weak_protocols)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic protocol (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    glitch_lib.traverse(var.value, weak_modes)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic mode (CWE-327)"
    }
}