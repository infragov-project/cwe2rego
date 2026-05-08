package glitch

import data.glitch_lib

weak_encryption_patterns := {"md5", "sha1", "des", "3des", "rc4", "aes-128", "tls 1.0", "tls 1.1", "ssl v2", "ssl v3", "md5_crypt"}

weak_network_patterns := {"TLS_1_0", "TLS_1_1", "SSLv2", "SSLv3", "DES-CBC3-SHA", "RC4-MD5"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    weak_attr_names := {"algorithm", "cipher", "kms_key_spec", "key_spec", "encryption_type", "version", "protocol", "ssl_policy", "tls_version"}
    weak_attr_names[attr.name]
    glitch_lib.traverse(attr.value, weak_encryption_patterns)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    network_attr_names := {"ssl_policy", "tls_version", "security_policy"}
    network_attr_names[attr.name]
    glitch_lib.traverse(attr.value, weak_network_patterns)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak network encryption settings. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_size_attr_names := {"key_length", "key_size", "rsa_key_size"}
    key_size_attr_names[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Small key size in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_disable_attr_names := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    encryption_disable_attr_names[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_disable_attr_names := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    encryption_disable_attr_names[attr.name]
    attr.value.ir_type == "String"
    attr.value.value == "false"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_disable_attr_names := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    encryption_disable_attr_names[attr.name]
    attr.value.ir_type == "String"
    attr.value.value == "none"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_disable_attr_names := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    encryption_disable_attr_names[attr.name]
    attr.value.ir_type == "String"
    attr.value.value == "disabled"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    secret_keywords := {"password", "secret", "key", "seed"}
    kw := secret_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), var.name)
    var.value.ir_type == "String"
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded secret in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    key_size_keywords := {"key_length", "key_size", "rsa_key_size"}
    kw := key_size_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), var.name)
    var.value.ir_type == "Integer"
    var.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Small key size in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_disable_keywords := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    kw := encryption_disable_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), var.name)
    var.value.ir_type == "Boolean"
    var.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Encryption disabled in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_disable_keywords := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    kw := encryption_disable_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), var.name)
    var.value.ir_type == "String"
    var.value.value == "false"
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Encryption disabled in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_disable_keywords := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    kw := encryption_disable_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), var.name)
    var.value.ir_type == "String"
    var.value.value == "none"
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Encryption disabled in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_disable_keywords := {"storage_encryption", "encryption_enabled", "server_side_encryption", "encrypted", "encrypt", "database_encryption"}
    kw := encryption_disable_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), var.name)
    var.value.ir_type == "String"
    var.value.value == "disabled"
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Encryption disabled in variable. (CWE-326)"
    }
}