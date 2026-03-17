package glitch

import data.glitch_lib

# Patterns for detection
weak_algorithm_pattern := ".*\\b(DES|3DES|RC4|MD5|SHA-1|AES-128|Blowfish|RC2|ARC4)\\b.*"
outdated_protocol_pattern := ".*\\b(TLSv1|TLSv1\\.1|SSLv2|SSLv3|SSHv1)\\b.*"
insufficient_key_pattern := ".*\\b1024\\b.*"
password_hash_pattern := ".*\\$1\\$.*"
disabled_encryption_pattern := ".*enabled.*:.*false.*"

# Helper rules
contains_weak_algorithm(value) {
    value.ir_type == "String"
    regex.match(weak_algorithm_pattern, value.value)
}

contains_outdated_protocol(value) {
    value.ir_type == "String"
    regex.match(outdated_protocol_pattern, value.value)
}

contains_insufficient_key(value) {
    value.ir_type == "String"
    regex.match(insufficient_key_pattern, value.value)
}

contains_md5_hash(value) {
    value.ir_type == "String"
    regex.match(password_hash_pattern, value.value)
}

contains_disabled_encryption(value) {
    value.ir_type == "String"
    regex.match(disabled_encryption_pattern, value.value)
}

# Rule for weak algorithms in content attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    contains_weak_algorithm(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm (CWE-326)"
    }
}

# Rule for weak algorithms in password attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "password"
    contains_weak_algorithm(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm (CWE-326)"
    }
}

# Rule for outdated protocols in content attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    contains_outdated_protocol(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of outdated encryption protocol (CWE-326)"
    }
}

# Rule for outdated protocols in password attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "password"
    contains_outdated_protocol(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of outdated encryption protocol (CWE-326)"
    }
}

# Rule for insufficient key lengths in content attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    contains_insufficient_key(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length (CWE-326)"
    }
}

# Rule for insufficient key lengths in password attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "password"
    contains_insufficient_key(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length (CWE-326)"
    }
}

# Rule for insufficient key lengths in command attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    contains_insufficient_key(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length (CWE-326)"
    }
}

# Rule for MD5 password hashes in password attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "password"
    contains_md5_hash(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of MD5 for password hashing (CWE-326)"
    }
}

# Rule for disabled encryption in content attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    contains_disabled_encryption(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption explicitly disabled (CWE-326)"
    }
}

# Rule for hard-coded keys in content attributes for file resources
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    attr.value.value != ""
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded encryption key in file content (CWE-326)"
    }
}

# Rule for hard-coded keys in command attributes for execute resources
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "execute"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    attr.value.value != ""
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded encryption key in command (CWE-326)"
    }
}