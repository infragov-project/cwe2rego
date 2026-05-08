package glitch

import data.glitch_lib

weak_algorithm_regex := "(?i)(des|3des|tdes|rc4|blowfish|ecb|md5|sha1|sslv3|tlsv1_0|tlsv1_1)"
weak_protocol_regex := "(?i)(http|ftp|sslv3|tlsv1_0|tlsv1_1)"
base64_pattern := "^[A-Za-z0-9+/]{20,}={0,2}$"
placeholder_strings := {"changeme", "password", "default", "example"}
key_length_attributes := {"key_length", "key_size", "bit_length", "key_spec"}
hardcoded_key_attributes := {"secret_key", "private_key", "keystore_password", "truststore_password", "password"}
weak_protocol_attributes := {"protocol", "ssl_policy", "tls_policy", "security_policy"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    not is_false_positive(attr)
    glitch_lib.traverse(attr.value, weak_algorithm_regex)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    not is_false_positive(variable)
    glitch_lib.traverse(variable.value, weak_algorithm_regex)
    result := {
        "type": "sec_weak_crypt",
        "element": variable,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in variable (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in key_length_attributes
    value := attr.value
    value.ir_type == "String"
    attr.name == "key_spec"
    regex.match("(?i)rsa_1024", value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in key_length_attributes
    value := attr.value
    value.ir_type == "Integer"
    attr.name != "key_spec"
    value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in hardcoded_key_attributes
    value := attr.value
    value.ir_type == "String"
    str_value := value.value
    str_lower := lower(str_value)
    placeholder := placeholder_strings[_]
    contains(str_lower, placeholder)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded key with placeholder detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in hardcoded_key_attributes
    value := attr.value
    value.ir_type == "String"
    str_value := value.value
    regex.match(base64_pattern, str_value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded key (base64 pattern) detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "auto_rotation_enabled"
    value := attr.value
    value.ir_type == "Boolean"
    value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Key auto-rotation is disabled (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in weak_protocol_attributes
    glitch_lib.traverse(attr.value, weak_protocol_regex)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak protocol or TLS version detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "hash_algorithm"
    value := attr.value
    value.ir_type == "String"
    glitch_lib.traverse(value, weak_algorithm_regex)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak hashing algorithm for key derivation (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "pbkdf2_iterations"
    value := attr.value
    value.ir_type == "Integer"
    value.value < 10000
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Low iteration count for key derivation (CWE-326)."
    }
}

is_false_positive(node) {
    node.ir_type == "Attribute"
    node.name == "shell"
    value := node.value
    value.ir_type == "String"
    regex.match(".*openssl.*-md md5.*", value.value)
}

is_false_positive(node) {
    node.ir_type == "Attribute"
    node.name == "vars_prompt"
}

is_false_positive(node) {
    node.ir_type == "Variable"
    regex.match(".*broadcast_address.*", node.name)
}