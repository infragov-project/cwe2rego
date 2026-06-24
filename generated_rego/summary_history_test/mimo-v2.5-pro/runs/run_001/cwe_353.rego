package glitch

import data.glitch_lib

data_transfer_attrs := {"url", "source", "artifact", "package", "download", "fetch", "get", "retrieve", "pull", "import", "remote"}
integrity_keys := {"gpgcheck", "gpgcheck_enabled", "checksum", "hash", "signature", "integrity", "verify_checksum", "checksum_algorithm", "checksum_type", "integrity_check"}
insecure_protocols := {"http://", "ftp://", "telnet://"}
disable_flags := {"insecure", "skip_verification", "allow_unverified", "bypass_validation", "no_verify"}
data_transfer_types := {"get_url", "remote_file", "git", "hg", "svn", "subversion", "docker_image", "archive", "fetch"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_data_transfer_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    not has_sibling_integrity(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check for data transfer - Use cryptographic verification to ensure data has not been tampered with in transit. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    not is_data_transfer_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == data_transfer_attrs[_]
    not has_sibling_integrity(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check for data transfer - Use cryptographic verification to ensure data has not been tampered with in transit. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == integrity_keys[_]
    is_integrity_disabled(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Integrity check explicitly disabled - Enable cryptographic verification to ensure data has not been tampered with. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    is_hash_entry(entry)
    entry.key.value == integrity_keys[_]
    is_integrity_disabled(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry,
        "path": parent.path,
        "description": "Integrity check explicitly disabled - Enable cryptographic verification to ensure data has not been tampered with. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == data_transfer_attrs[_]
    has_insecure_protocol(attr.value)
    not has_sibling_integrity(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure protocol without integrity verification - Use a secure protocol or add integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    is_hash_entry(entry)
    entry.key.value == disable_flags[_]
    is_true_value(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry,
        "path": parent.path,
        "description": "Integrity verification explicitly disabled - Enable cryptographic verification to ensure data has not been tampered with. (CWE-353)"
    }
}

is_data_transfer_type(type) {
    type == data_transfer_types[_]
}

is_hash_entry(entry) {
    entry.key.ir_type == "String"
    entry.value.ir_type != null
}

has_sibling_integrity(attrs) {
    attr := attrs[_]
    attr.name == integrity_keys[_]
}

has_insecure_protocol(value) {
    value.ir_type == "String"
    startswith(lower(value.value), insecure_protocols[_])
}

has_insecure_protocol(value) {
    value.ir_type == "Sum"
    walk(value, [_, child])
    child.ir_type == "String"
    startswith(lower(child.value), insecure_protocols[_])
}

is_integrity_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_integrity_disabled(value) {
    value.ir_type == "Null"
}

is_integrity_disabled(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "none"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "null"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "skip"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "disable"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "ignore"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "0"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_integrity_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "disabled"
}

is_true_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_true_value(value) {
    value.ir_type == "String"
    lower(value.value) == "true"
}