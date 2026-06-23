package glitch

import data.glitch_lib
import future.keywords.in

weak_algorithms := {"DES", "3DES", "TRIPLEDES", "RC2", "RC4", "BLOWFISH", "MD5", "SHA1", "SHA-1"}

weak_tls_versions := {"TLSV1.0", "TLSV1.1", "SSLV3", "SSLV2", "TLS1.0", "TLS1.1", "SSL3", "SSL2", "TLSV1", "TLSV2", "SSL23", "TLS1"}

weak_algos_exact := {"MD5", "SHA1", "SHA-1", "DES", "3DES", "TRIPLEDES", "RC2", "RC4", "BLOWFISH"}

weak_cipher_patterns := {"_RC4_", "_3DES_", "_DES_", "_EXPORT_", "_NULL_", "_anon_", "CBC_SHA"}

weak_protocols := {"PLAINTEXT", "HTTP", "FTP", "TELNET"}

weak_encryption_values := {"md5_crypt", "des_crypt", "sha1_crypt"}

weak_auth_method_values := {"md5", "des", "sha1"}

crypto_context_attrs := {"encrypt", "auth_method", "algorithm", "cipher", "hash", "digest", "checksum", "signature", "kdf", "key_derivation", "cipher_suites", "tls_version", "ssl_policy", "min_tls_version"}

name_keys := {"name", "prompt", "description", "title", "label"}

is_crypto_context_attribute(name) {
    lower_name := lower(name)
    some attr in crypto_context_attrs
    lower_name == attr
}

is_name_key(name) {
    lower_name := lower(name)
    some nk in name_keys
    lower_name == nk
}

contains_weak_algo(val) {
    upper_val := upper(val)
    some algo in weak_algorithms
    contains(upper_val, algo)
}

is_weak_tls_version(val) {
    upper_trim := upper(trim_space(val))
    upper_trim in weak_tls_versions
}

is_direct_weak_hash_call(node) {
    node.ir_type == "FunctionCall"
    fn_name := upper(node.name)
    fn_name in weak_algos_exact
}

is_weak_encryption_value(val) {
    val_lower := lower(val)
    val_lower in weak_encryption_values
}

is_weak_auth_method_value(val) {
    val_lower := lower(val)
    val_lower in weak_auth_method_values
}

string_has_weak_cipher(val) {
    val_upper := upper(val)
    some pattern in weak_cipher_patterns
    contains(val_upper, pattern)
}

is_hash_function_call(node) {
    node.ir_type == "FunctionCall"
    fn_lower := lower(node.name)
    contains(fn_lower, "hash")
}

get_string_value(node) = val {
    node.ir_type == "String"
    val := node.value
} else = val {
    node.ir_type == "VariableReference"
    val := node.value
}

# Check if node is a value of a key with given name
is_value_of_key(node, parent, keyname) {
    parent.ir_type == "Hash"
    some k
    entry := parent.value[k]
    entry.value == node
    entry.key.ir_type == "String"
    entry.key.value == keyname
} else {
    parent.ir_type == "KeyValue"
    parent.value == node
    parent.name == keyname
} else {
    parent.ir_type == "Attribute"
    parent.value == node
    parent.name == keyname
}

# Get the key name that this node is a value of
get_key_for_value(node, parent) = keyname {
    parent.ir_type == "Hash"
    some k
    entry := parent.value[k]
    entry.value == node
    entry.key.ir_type == "String"
    keyname := entry.key.value
} else = keyname {
    parent.ir_type == "KeyValue"
    parent.value == node
    keyname := parent.name
} else = keyname {
    parent.ir_type == "Attribute"
    parent.value == node
    keyname := parent.name
}

# Find parent of specific ir_type
find_parent_of_type(node, root, type) = parent {
    walk(root, [_, candidate])
    candidate.ir_type == type
    candidate != node
    contains_child(candidate, node)
}

# Generic child containment check
contains_child(parent, child) {
    parent.ir_type == "Hash"
    some k
    entry := parent.value[k]
    entry == child
} else {
    parent.ir_type == "Array"
    some i
    parent.value[i] == child
} else {
    parent.ir_type == "KeyValue"
    parent.value == child
} else {
    parent.ir_type == "Attribute"
    parent.value == child
} else {
    parent.ir_type == "FunctionCall"
    some i
    parent.args[i] == child
} else {
    parent.ir_type == "MethodCall"
    some i
    parent.args[i] == child
} else {
    parent.ir_type == "BlockExpr"
    some i
    parent.statements[i] == child
}

# Rule 1: Direct calls to weak hash functions like md5(), sha1()
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, fcnode])
    fcnode.ir_type == "FunctionCall"
    is_direct_weak_hash_call(fcnode)

    result := {
        "type": "sec_weak_crypt",
        "element": fcnode,
        "path": parent.path,
        "description": "Use of weak cryptographic hash function - Direct calls to weak hash functions like md5() or sha1() provide inadequate encryption strength. (CWE-326)"
    }
}

# Rule 2: Hash function calls with weak algorithm arguments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, fcnode])
    fcnode.ir_type == "FunctionCall"
    is_hash_function_call(fcnode)
    
    some fc_arg in fcnode.args
    fc_arg.ir_type == "String"
    arg_upper := upper(fc_arg.value)
    arg_upper in weak_algos_exact

    result := {
        "type": "sec_weak_crypt",
        "element": fcnode,
        "path": parent.path,
        "description": "Use of weak cryptographic hash algorithm in function call - Weak or deprecated cryptographic algorithms can lead to inadequate encryption strength. (CWE-326)"
    }
}

# Rule 3: String values in crypto context attributes (Hash entries)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, strnode])
    strnode.ir_type == "String"
    val := strnode.value

    # Must be a weak crypto value
    is_weak_encryption_value(val)

    # Verify it's assigned to a crypto context key
    walk(parent, [_, ancestor])
    contains_child(ancestor, strnode)
    keyname := get_key_for_value(strnode, ancestor)
    is_crypto_context_attribute(keyname)

    result := {
        "type": "sec_weak_crypt",
        "element": strnode,
        "path": parent.path,
        "description": "Use of weak encryption algorithm in configuration - Weak encryption methods like md5_crypt provide inadequate protection. (CWE-326)"
    }
}

# Rule 4: auth_method Attribute with weak value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == "auth_method"
    attr.value.ir_type == "String"
    val_str := attr.value.value
    is_weak_auth_method_value(val_str)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak authentication method - MD5-based authentication provides inadequate encryption strength. (CWE-326)"
    }
}

# Rule 5: KeyValue with crypto context name and weak value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, kv])
    kv.ir_type == "KeyValue"
    is_crypto_context_attribute(kv.name)
    kv.value.ir_type == "String"
    val_str := kv.value.value

    # Must be actually weak
    is_weak_encryption_value(val_str)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of weak encryption algorithm in KeyValue - Weak encryption methods like md5_crypt provide inadequate protection. (CWE-326)"
    }
}

# Rule 6: Variables with crypto-relevant names containing weak cipher patterns
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, varnode])
    varnode.ir_type == "Variable"
    var_name := lower(varnode.name)
    some ctx in crypto_context_attrs
    contains(var_name, ctx)
    varnode.value.ir_type == "String"
    val_str := varnode.value.value
    string_has_weak_cipher(val_str)

    result := {
        "type": "sec_weak_crypt",
        "element": varnode,
        "path": parent.path,
        "description": "Use of weak cipher suite in variable - TLS/SSL cipher suites with weak algorithms provide inadequate encryption strength. (CWE-326)"
    }
}

# Rule 7: String values with weak cipher patterns in crypto context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, strnode])
    strnode.ir_type == "String"
    val := strnode.value

    # Must have weak cipher pattern
    string_has_weak_cipher(val)

    # Verify it's in crypto context, not a name field
    walk(parent, [_, ancestor])
    contains_child(ancestor, strnode)
    keyname := get_key_for_value(strnode, ancestor)
    is_crypto_context_attribute(keyname)
    not is_name_key(keyname)

    result := {
        "type": "sec_weak_crypt",
        "element": strnode,
        "path": parent.path,
        "description": "Use of weak cipher suite containing insecure algorithm pattern - TLS/SSL cipher suites with deprecated algorithms provide inadequate encryption strength. (CWE-326)"
    }
}

# Rule 8: Access nodes with weak algorithm in key (e.g., ['password_md5'])
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, access_node])
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    key_str := access_node.right.value
    contains_weak_algo(key_str)
    not is_probably_name_in_access_key(key_str)

    result := {
        "type": "sec_weak_crypt",
        "element": access_node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm in data access key - Accessing data with keys containing weak algorithm names indicates potential use of weak cryptography. (CWE-326)"
    }
}

# Helper: check if access key is probably just a name/description
is_probably_name_in_access_key(key_str) {
    lower_key := lower(key_str)
    contains(lower_key, "_name_")
} else {
    lower_key := lower(key_str)
    contains(lower_key, "prompt")
} else {
    lower_key := lower(key_str)
    contains(lower_key, "title")
} else {
    lower_key := lower(key_str)
    contains(lower_key, "label_")
}

# Rule 9: Cipher suite strings in TLS/SSL configurations (Array or String values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "String"
    val := node.value
    string_has_weak_cipher(val)

    # Check parent context is cipher-related
    walk(parent, [_, ancestor])
    contains_child(ancestor, node)
    keyname := get_key_for_value(node, ancestor)
    cipher_related := {"cipher", "cipher_suites", "ssl_cipher", "tls_cipher", "crypto"}
    some cipher_key in cipher_related
    contains(lower(keyname), cipher_key)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cipher suite in TLS/SSL configuration - Deprecated cipher algorithms provide inadequate encryption strength. (CWE-326)"
    }
}

# Rule 10: TLS/SSL version configuration with weak versions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "String"
    val := node.value
    is_weak_tls_version(val)

    walk(parent, [_, ancestor])
    contains_child(ancestor, node)
    keyname := get_key_for_value(node, ancestor)
    tls_related := {"tls_version", "ssl_version", "min_tls_version", "min_ssl_version", "security_policy"}
    some tls_key in tls_related
    contains(lower(keyname), tls_key)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak TLS/SSL version - Deprecated TLS versions provide inadequate encryption strength. (CWE-326)"
    }
}

# Rule 11: AtomicUnit attributes with weak crypto values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    
    some attr in au.attributes
    is_crypto_context_attribute(attr.name)
    attr.value.ir_type == "String"
    val_str := attr.value.value
    is_weak_value_for_crypto_context(val_str, attr.name)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic configuration in resource - Weak algorithms or methods provide inadequate encryption strength. (CWE-326)"
    }
}

# Helper: check if value is weak for given crypto context
is_weak_value_for_crypto_context(val, attr_name) {
    is_weak_encryption_value(val)
} else {
    is_weak_auth_method_value(val)
} else {
    is_weak_tls_version(val)
}