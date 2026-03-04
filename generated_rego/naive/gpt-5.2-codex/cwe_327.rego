package glitch

import data.glitch_lib

weak_crypto_tokens := {
    "md2",
    "md4",
    "md5",
    "sha[-_]?1",
    "ripemd",
    "crc32",
    "des",
    "3des",
    "rc2",
    "rc4",
    "idea",
    "tea",
    "blowfish",
    "xor",
    "rot",
    "rot13",
    "null",
    "export",
    "sslv2",
    "sslv3",
    "ssl",
    "tls1\\.0",
    "tls1\\.1",
    "tlsv1\\.0",
    "tlsv1\\.1",
    "ecb",
    "cbc",
    "pkcs1v1\\.5",
    "pbeWithMD5",
    "pbe-with-md5",
    "pbe_with_md5",
    "base64"
}

key_size_keywords := {
    "key_size",
    "key_length",
    "key_bits",
    "key_spec",
    "modulus_length",
    "modulus",
    "keysize",
    "bits"
}

weak_flag_keywords := {
    "legacy",
    "compatibility",
    "weak",
    "allow_weak",
    "insecure",
    "allow_insecure"
}

match_token(str) {
    token := weak_crypto_tokens[_]
    glitch_lib.contains(str, token)
}

has_weak_crypto(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    match_token(n.value)
}

has_weak_crypto(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
    match_token(n.value)
}

has_weak_crypto(node) {
    walk(node, [_, n])
    n.ir_type == "FunctionCall"
    match_token(n.name)
}

has_weak_crypto(node) {
    walk(node, [_, n])
    n.ir_type == "MethodCall"
    match_token(n.method)
}

weak_crypto_kv(kv) {
    has_weak_crypto(kv.value)
}

weak_crypto_kv(kv) {
    match_token(kv.name)
}

is_key_size_field(name) {
    kw := key_size_keywords[_]
    glitch_lib.contains(name, kw)
}

weak_key_size_value(val) {
    val.ir_type == "Integer"
    val.value <= 1024
}

weak_key_size_value(val) {
    val.ir_type == "Float"
    val.value <= 1024
}

weak_key_size_value(val) {
    val.ir_type == "String"
    regex.match("^[0-9]+$", val.value)
    num := to_number(val.value)
    num <= 1024
}

weak_key_size_value(val) {
    val.ir_type == "String"
    regex.match("(?i).*(1024|768|512|256|224|192|160|128).*", val.value)
}

is_weak_flag_field(name) {
    kw := weak_flag_keywords[_]
    glitch_lib.contains(name, kw)
}

weak_flag_value(val) {
    val.ir_type == "Boolean"
    val.value == true
}

weak_flag_value(val) {
    val.ir_type == "String"
    regex.match("(?i).*(true|yes|enable|enabled|allow|on).*", val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    weak_crypto_kv(kv)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm or protocol - Avoid obsolete/weak crypto settings. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    weak_crypto_kv(kv)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm or protocol - Avoid obsolete/weak crypto settings. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    is_key_size_field(kv.name)
    weak_key_size_value(kv.value)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of weak cryptographic key size - Avoid small key sizes for cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    is_key_size_field(kv.name)
    weak_key_size_value(kv.value)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of weak cryptographic key size - Avoid small key sizes for cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    kv := attrs[_]
    is_weak_flag_field(kv.name)
    weak_flag_value(kv.value)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Weak/legacy crypto options enabled - Avoid allowing weak or legacy cryptographic settings. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    kv := vars[_]
    is_weak_flag_field(kv.name)
    weak_flag_value(kv.value)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Weak/legacy crypto options enabled - Avoid allowing weak or legacy cryptographic settings. (CWE-327)"
    }
}