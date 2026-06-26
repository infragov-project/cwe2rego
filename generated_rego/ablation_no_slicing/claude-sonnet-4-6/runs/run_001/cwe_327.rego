package glitch

import data.glitch_lib

weak_crypto_pattern := `(?i).*(DES|3DES|TDES|TDEA|TripleDES|RC2|RC4|RC5|ARC4|ARCFOUR|Blowfish|IDEA|Skipjack|TEA|XTEA|\bECB\b|EXPORT|MD2|MD4|MD5|SHA-?1[^0-9]|SHA-?1$|SHA1with|MD5with|HMAC-MD5|HMAC-SHA1|RSA-1024|md5_crypt|sha1_crypt|CBC_SHA|WITH_RC4|WITH_DES).*`

deprecated_protocol_pattern := `(?i).*(SSLv?2|SSLv?3|TLSv?1(\.0)?|TLSv?1\.1|ELBSecurityPolicy-2015-05|ELBSecurityPolicy-TLS-1-0-2015-04|ELBSecurityPolicy-TLS-1-1-2017-01).*`

crypto_name_pattern := `(?i)(algo|cipher|crypt|encrypt|hash|digest|protocol|tls|ssl|signing_alg|certificate_alg|key_type|key_algorithm|auth_method|auth_type)`

encryption_flag_pattern := `(?i)(^encrypted$|enable_encryption|encryption_enabled|at_rest_encryption|in_transit_encryption|storage_encrypted)`

key_size_pattern := `(?i)(key_size|key_length|key_bits|bit_length|rsa_bits|dh_bits|modulus_length|key_strength)`

weak_func_name_pattern := `(?i)^(md2|md4|md5|sha1|sha_1|sha-1)$`

var_name_algo_pattern := `(?i)(^|[_\-])(md2|md4|md5|sha1|sha_1|sha\-1|3des|tdes|rc4|rc2|arcfour|arc4)([_\-]|$)`

is_weak_crypto_string(v) {
    v.ir_type == "String"
    regex.match(weak_crypto_pattern, v.value)
}

is_deprecated_protocol_string(v) {
    v.ir_type == "String"
    regex.match(deprecated_protocol_pattern, v.value)
}

is_weak_algo_func(v) {
    v.ir_type == "FunctionCall"
    regex.match(weak_func_name_pattern, v.name)
}

is_weak_hash_call(v) {
    v.ir_type == "FunctionCall"
    regex.match(`(?i)hash`, v.name)
    arg := v.args[_]
    arg.ir_type == "String"
    regex.match(`(?i)^(md2|md4|md5|sha-?1)$`, arg.value)
}

is_weak_access_key(v) {
    v.ir_type == "Access"
    v.right.ir_type == "String"
    regex.match(weak_crypto_pattern, v.right.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_name_pattern, attr.name)
    is_weak_crypto_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_name_pattern, attr.name)
    is_deprecated_protocol_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a deprecated TLS/SSL protocol version. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_weak_algo_func(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak hash algorithm function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_weak_hash_call(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak hash algorithm in filter or function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_weak_access_key(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm referenced via access key. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    hash_entry := attr.value.value[_]
    hash_entry.ir_type == "Hash"
    kv := hash_entry.value[_]
    kv.key.ir_type == "String"
    regex.match(crypto_name_pattern, kv.key.value)
    is_weak_crypto_string(kv.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm in nested configuration. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(crypto_name_pattern, v.name)
    is_weak_crypto_string(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm in variable assignment. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(crypto_name_pattern, v.name)
    is_deprecated_protocol_string(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a deprecated TLS/SSL protocol in variable assignment. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_weak_algo_func(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a weak hash algorithm function in variable assignment. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(var_name_algo_pattern, v.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm referenced in variable name. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(encryption_flag_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key length. (CWE-327)"
    }
}