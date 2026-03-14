package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "TripleDES", "RC4", "ARC4", "Blowfish", "IDEA", "MD5", "SHA-1", "SHA1"}
weak_protocols := {"SSLv2", "SSLv3", "TLS_1_0", "TLS_1_1", "TLSv1", "TLSv1.1"}
weak_modes := {"ECB"}
weak_hashing := {"MD5", "SHA-1", "SHA1"}
weak_key_size_values := {56, 64, 112, 1024, 160}
weak_key_size_strings := {"56", "64", "112", "1024", "160"}

all_weak_patterns := weak_algorithms | weak_protocols | weak_modes | weak_hashing | weak_key_size_strings

contains_weak_pattern(str) {
    some i
    pattern := all_weak_patterns[i]
    regex.match(sprintf("(?i).*%s.*", [pattern]), str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "String"
    contains_weak_pattern(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption setting detected - Use of deprecated or weak cryptographic algorithm, protocol, key size, or mode. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "Integer"
    some i
    n.value == weak_key_size_values[i]
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption setting detected - Use of deprecated or weak cryptographic algorithm, protocol, key size, or mode. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "Hash"
    some i
    pair := n.value[i]
    pair.value.ir_type == "String"
    contains_weak_pattern(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent.path,
        "description": "Weak encryption setting detected in hash value. (CWE-326)"
    }
}