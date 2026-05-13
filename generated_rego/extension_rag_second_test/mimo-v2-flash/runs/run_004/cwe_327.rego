package glitch

import data.glitch_lib

weak_patterns := {"(?i)\\bdes\\b", "(?i)\\b3des\\b", "(?i)\\btriple\\.des\\b", "(?i)\\brc4\\b", "(?i)\\brc2\\b", "(?i)\\bmd5\\b", "(?i)\\bsha1\\b", "(?i)\\bsha-1\\b", "(?i)\\bsslv2\\b", "(?i)\\bsslv3\\b", "(?i)\\btls.?1.?0\\b", "(?i)\\btls.?1.?1\\b", "(?i)\\baes-ecb\\b", "(?i)\\belbsecuritypolicy-2016-08\\b", "(?i)\\btls_1_0\\b", "(?i)\\btls_1_1\\b", "(?i)\\bsecp112r1\\b", "(?i)\\bprime192v1\\b", "(?i)\\bmd5_crypt\\b"}

crypto_attrs := {"algorithm", "hashing", "protocol", "encryption", "key_length", "curve", "password_hash", "ssl_policy", "tls_version", "min_protocol_version", "server_side_encryption", "sse_algorithm", "kms_key_id", "database_encryption", "rotation_period", "automatic_key_rotation", "encrypt", "cipher_suites", "password", "private_key", "truststore_password", "keystore_password"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr_lower := lower(attr.name)
    attr_matches := count({x | x := crypto_attrs[_]; contains(attr_lower, x)}) > 0
    attr_matches
    glitch_lib.traverse(attr.value, weak_patterns[_])
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
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var_lower := lower(var.name)
    var_matches := count({x | x := crypto_attrs[_]; contains(var_lower, x)}) > 0
    var_matches
    glitch_lib.traverse(var.value, weak_patterns[_])
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
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    contains(lower_name, "key_length")
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure key size (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    contains(lower_name, "encryption")
    attr.value.ir_type == "String"
    attr.value.value == "none"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure encryption configuration (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    contains(lower_name, "sse_algorithm")
    attr.value.ir_type == "String"
    attr.value.value == "none"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure encryption configuration (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    contains(lower_name, "database_encryption")
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure encryption configuration (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    contains(lower_name, "password")
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded cryptographic secret (CWE-327)"
    }
}