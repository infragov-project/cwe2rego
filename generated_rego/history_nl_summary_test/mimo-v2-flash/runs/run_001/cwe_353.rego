package glitch

import data.glitch_lib

insecure_protocols := {"http://", "ftp://", "telnet://"}

security_feature_flags := {"enable_ssl", "use_tls", "secure_connection", "verify_checksum", "integrity_check", "checksum_algorithm", "gpgcheck", "gpg_check", "ssl", "tls", "validate_certs", "verify"}

data_transfer_attrs := {"url", "endpoint", "connection_string", "baseurl", "source", "mirrorlist", "source_url", "download_url", "path"}

integrity_attrs := {"checksum", "signature", "verify_payload", "integrity_check", "checksum_algorithm", "gpgcheck", "gpg_check", "integrity_mode", "checksum_validation", "hash_verification", "verify"}

data_transfer_types := {"remote_file", "file", "cookbook_file", "get_url", "archive", "package", "yumrepo", "remote_file", "s3_bucket", "azure_blob"}

check_insecure_protocol(value) {
    value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", value.value)
} else {
    value.ir_type == "Sum"
    check_sum_for_insecure_protocol(value)
}

check_sum_for_insecure_protocol(sum_node) {
    walk(sum_node, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", n.value)
}

check_security_flag(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    regex.match("(?i)^(disabled|none|0|no)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

has_any_integrity_attribute(attrs) {
    attr := attrs[_]
    integrity_attrs[attr.name]
}

# Detect insecure protocols in data transfer attributes (Attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    data_transfer_attrs[node.name]
    check_insecure_protocol(node.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Use of insecure protocol (HTTP, FTP, Telnet) without integrity check. (CWE-353)"
    }
}

# Detect insecure protocols in data transfer attributes (Variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    data_transfer_attrs[node.name]
    check_insecure_protocol(node.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Use of insecure protocol (HTTP, FTP, Telnet) without integrity check. (CWE-353)"
    }
}

# Detect insecure protocols in nested Hash configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    kv := hash.value[_]
    kv.key.ir_type == "String"
    data_transfer_attrs[kv.key.value]
    check_insecure_protocol(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of insecure protocol (HTTP, FTP, Telnet) without integrity check in nested configuration. (CWE-353)"
    }
}

# Detect disabled security features in Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    security_feature_flags[node.name]
    check_security_flag(node.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Security feature (SSL/TLS, integrity check) is disabled. (CWE-353)"
    }
}

# Detect disabled security features in Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    security_feature_flags[node.name]
    check_security_flag(node.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Security feature (SSL/TLS, integrity check) is disabled. (CWE-353)"
    }
}

# Detect disabled security features in nested Hash configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    kv := hash.value[_]
    kv.key.ir_type == "String"
    security_feature_flags[kv.key.value]
    check_security_flag(kv.value)
    result := {
        "type": "sec_no_int_check",
        "element": kv.value,
        "path": parent.path,
        "description": "Security feature (SSL/TLS, integrity check) is disabled in nested configuration. (CWE-353)"
    }
}

# Detect data transfer resources without integrity attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    data_transfer_types[unit.type]
    attrs := glitch_lib.all_attributes(unit)
    not has_any_integrity_attribute(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": unit,
        "path": parent.path,
        "description": "Data transfer resource without integrity attributes. (CWE-353)"
    }
}