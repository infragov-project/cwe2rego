package glitch

import data.glitch_lib

weak_ciphers := {"tlsv1.0", "tlsv1.1", "ssl2", "ssl3", "rc4", "3des", "des", "md5", "null", "export", "aes128-cbc", "hmac-sha1"}

check_weak_string(s) {
    cipher := weak_ciphers[_]
    regex.match(sprintf("(?i)\\b%s\\b", [cipher]), s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    lines := split(attr.value.value, "\n")
    line := lines[_]
    not regex.match("^\\s*#", line)
    check_weak_string(line)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption configuration found in content. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "loop"
    attr.value.ir_type == "Array"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    check_weak_string(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption configuration found in loop. (CWE-326)"
    }
}