package glitch

import data.glitch_lib

weak_crypto_vals := {"des", "3des", "md5", "sha1", "rc4", "aes-128-ecb", "aes-256-ecb", "ecb", "rsa-1024", "tea", "xor", "rot13", "rot-13", "rot25", "rot-25", "md4", "sha-1", "sha-0", "dsa-1024", "md5_crypt", "md5crypt", "sha", "des_cbc", "des_cfb", "des_ofb", "des_ecb", "rc2", "rc5"}

weak_crypto_patterns := ["(?i)\\bdes\\b", "(?i)\\bmd5\\b", "(?i)\\bsha1\\b", "(?i)\\brc4\\b", "(?i)aes.*ecb", "(?i)rsa.*1024", "(?i)\\btea\\b", "(?i)\\bxor\\b", "(?i)\\brot13\\b", "(?i)\\brot-13\\b", "(?i)\\brot25\\b", "(?i)\\brot-25\\b", "(?i)\\bmd4\\b", "(?i)sha[^2-9]", "(?i)sha$", "(?i)dsa.*1024", "(?i)md5_crypt", "(?i)md5crypt", "(?i)sha[^2-9]", "(?i)_sha\\b", "(?i)\\bsha_", "(?i)_md5\\b", "(?i)\\bmd5_"]

crypto_context_names := {"encryption", "encrypt", "cipher", "algorithm", "crypto", "hash", "digest", "signature", "ssl_protocol", "tls_version", "key_exchange", "kex", "mac", "hmac", "cipher_suites", "password", "cert_algorithm", "auth_method", "checksum", "encrypt", "decrypt", "verify", "sign", "ssl", "tls", "auth"}

matches_weak_crypto(val) {
    lower_val := lower(val)
    weak_crypto_vals[lower_val]
}

matches_weak_crypto(val) {
    pattern := weak_crypto_patterns[_]
    regex.match(pattern, val)
}

is_crypto_context(name) {
    lower_name := lower(name)
    crypto_context_names[lower_name]
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "encrypt")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "cipher")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "ssl")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "tls")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "crypto")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "hash")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "digest")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "auth")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "password")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "kex")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "verify")
}

is_crypto_context(name) {
    lower_name := lower(name)
    contains(lower_name, "sign")
}

is_vars_prompt_encrypt_key(name) {
    lower(name) == "encrypt"
}

get_string_value(node) = val {
    node.ir_type == "String"
    val := node.value
}

get_string_value(node) = val {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    val := node.right.value
}

collect_all_strings(node, vals) {
    node.ir_type == "String"
    vals := {node.value}
}

collect_all_strings(node, vals) {
    node.ir_type == "Array"
    vals := {s |
        some i
        child := node.value[i]
        child_vals := collect_all_strings(child)
        s := child_vals[_]
    }
}

collect_all_strings(node, vals) {
    node.ir_type == "Hash"
    vals := {s |
        some i
        kv := node.value[i]
        key_vals := collect_all_strings(kv.key)
        val_vals := collect_all_strings(kv.value)
        s := key_vals[_]
    }
}

collect_all_strings(node, vals) {
    node.ir_type == "Hash"
    vals := {s |
        some i
        kv := node.value[i]
        key_vals := collect_all_strings(kv.key)
        val_vals := collect_all_strings(kv.value)
        s := val_vals[_]
    }
}

collect_all_strings(node, vals) {
    node.ir_type == "FunctionCall"
    vals := {s |
        some i
        arg := node.args[i]
        arg_vals := collect_all_strings(arg)
        s := arg_vals[_]
    }
}

collect_all_strings(node, vals) {
    node.ir_type == "VariableReference"
    vals := {node.value}
}

collect_all_strings(node, vals) {
    not {"String", "Array", "Hash", "FunctionCall", "Access", "VariableReference"}[node.ir_type]
    vals := set()
}

collect_all_strings(node) = vals {
    vals := {s |
        walk(node, [_, leaf])
        leaf.ir_type == "String"
        s := leaf.value
    }
}

has_weak_in_value_or_children(node) {
    s := collect_all_strings(node)[_]
    matches_weak_crypto(s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    
    func_name := lower(node.name)
    matches_weak_crypto(func_name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Function '%s' is a weak cryptographic algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as MD5 or SHA1. (CWE-327)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    
    some i
    arg := node.args[i]
    arg.ir_type == "String"
    matches_weak_crypto(arg.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Function '%s' called with weak algorithm argument '%s'. Avoid using weak, broken, or obsolete cryptographic algorithms such as MD5 or SHA1. (CWE-327)", [node.name, arg.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    
    is_crypto_context(attr_name)
    s := collect_all_strings(node.value)[_]
    matches_weak_crypto(s)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Attribute '%s' in cryptographic context uses weak algorithm '%s'. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [attr_name, s])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    
    is_vars_prompt_encrypt_key(attr_name)
    s := collect_all_strings(node.value)[_]
    matches_weak_crypto(s)
    
    not is_vars_prompt_context(path)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - vars_prompt encrypt uses weak algorithm '%s'. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [s])
    }
}

is_vars_prompt_context(path) {
    some i
    p := path[i]
    p.ir_type == "Attribute"
    p.name == "vars_prompt"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    
    s := collect_all_strings(node)[_]
    matches_weak_crypto(s)
    matches_weak_crypto(node.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Attribute name '%s' contains weak cryptographic algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    var_name := node.name
    
    is_crypto_context(var_name)
    s := collect_all_strings(node.value)[_]
    matches_weak_crypto(s)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Variable '%s' in cryptographic context uses weak algorithm '%s'. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [var_name, s])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    matches_weak_crypto(node.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Variable name '%s' indicates weak cryptographic algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    key_name := kv.key.value
    
    is_crypto_context(key_name)
    s := collect_all_strings(kv.value)[_]
    matches_weak_crypto(s)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Hash key '%s' uses weak algorithm '%s'. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [key_name, s])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    key_name := kv.key.value
    
    is_vars_prompt_encrypt_key(key_name)
    s := collect_all_strings(kv.value)[_]
    matches_weak_crypto(s)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Hash key 'encrypt' uses weak algorithm '%s'. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [s])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    some i
    kv := node.value[i]
    kv.key.ir_type == "String"
    matches_weak_crypto(kv.key.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Hash key name '%s' indicates weak algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [kv.key.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    s := node.value
    
    matches_weak_crypto(s)
    
    some i
    i > 0
    p := path[i]
    {"Attribute", "Variable", "KeyValue"}[p.ir_type]
    is_crypto_context(p.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - String '%s' in crypto context uses weak algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [s])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    s := node.value
    
    matches_weak_crypto(s)
    
    some i, j
    j := i + 1
    j < count(path)
    {"Hash", "Array"}[path[i].ir_type]
    child_key := path[j]
    {"KeyValue"}[child_key.ir_type]
    is_crypto_context(child_key.key.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - String '%s' in nested crypto context uses weak algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [s])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    access_name := node.right.value
    
    matches_weak_crypto(access_name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of a Broken or Risky Cryptographic Algorithm - Access to field '%s' indicates weak cryptographic algorithm. Avoid using weak, broken, or obsolete cryptographic algorithms such as DES, MD5, SHA1, RC4, or ECB mode. (CWE-327)", [access_name])
    }
}