package glitch

import data.glitch_lib

insecure_protocols = {"http", "ftp", "udp"}
disabled_integrity_flags = {"disable_checksum", "integrity_check", "enable_tls", "gpgcheck", "ssl_verify", "tls_validate", "validate_certs"}
weak_algorithms = {"md5", "sha1"}
data_related_attributes_for_insecure = {"url", "baseurl", "mirrorlist", "source"}
data_related_attributes = {"source", "url", "baseurl", "mirrorlist"}
integrity_attributes = {"checksum", "validation", "integrity", "versioning", "checksum_algorithm", "gpgcheck"}

has_insecure_protocol_string(str_val) {
    regex.match(".*(http://|ftp://|udp://).*", str_val)
} else {
    insecure_protocols[_] == str_val
}

is_value_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    value.ir_type == "String"
    value.value == "disabled"
} else {
    value.ir_type == "String"
    value.value == "no"
}

find_key_values(node) = kvs {
    kvs := {kv |
        walk(node, [path, n])
        n.ir_type in {"Attribute", "Variable"}
        kv := n
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    key_values := find_key_values(parent)
    kv := key_values[_]
    data_related_attributes_for_insecure[_] == kv.name
    kv.value.ir_type == "String"
    has_insecure_protocol_string(kv.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Unprotected data transmission - Protocol lacks integrity checks (e.g., HTTP, FTP, UDP without TLS). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    key_values := find_key_values(parent)
    kv := key_values[_]
    disabled_integrity_flags[_] == kv.name
    is_value_disabled(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Explicitly disabled integrity features - Checksum or integrity check is turned off. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    key_values := find_key_values(parent)
    kv := key_values[_]
    kv.value.ir_type == "String"
    weak_algorithms[_] == kv.value.value
    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Weak integrity algorithm - Using outdated/broken algorithms (e.g., MD5, SHA1) for integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    key_values := find_key_values(parent)
    has_data_attr := count({kv | kv := key_values[_]; data_related_attributes[_] == kv.name}) > 0
    has_integrity_attr := count({kv | kv := key_values[_]; integrity_attributes[_] == kv.name}) > 0
    has_data_attr == true
    has_integrity_attr == false
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": "Storage integrity omission - Cloud storage or database lacks versioning/checksum/validation settings. (CWE-353)"
    }
}