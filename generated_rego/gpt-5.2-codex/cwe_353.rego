package glitch

import data.glitch_lib

insecure_protocols := {"udp", "http", "ftp", "tftp", "telnet", "smtp", "snmp", "syslog", "raw"}
protocol_keywords := {"protocol", "transport", "listener", "endpoint", "service", "port", "scheme"}
integrity_keywords := {"checksum", "integrity", "hash", "digest", "signature", "signed", "mac", "hmac", "message_authentication", "verify", "validation", "etag", "content_md5", "data_integrity", "crc", "tls", "ssl", "dtls", "ipsec", "encryption", "encrypt"}
disable_keywords := {"disable", "skip", "ignore", "allow_unverified", "unverified", "no_verify", "no_validation", "no_integrity", "no_checksum"}
transfer_keywords := {"replication", "transfer", "sync", "backup"}
true_strings := {"true", "1", "yes", "on", "enable", "enabled"}
false_strings := {"false", "0", "off", "none", "disable", "disabled", "no", "", "skip", "ignore"}

contains_keyword(name, keywords) {
    kw := keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), name)
}

all_keyvalues(node) = kvs {
    attrs := glitch_lib.all_attributes(node)
    vars := glitch_lib.all_variables(node)
    kvs := attrs | vars
}

insecure_protocol_string(v) {
    v.ir_type == "String"
    proto := lower(v.value)
    proto == insecure_protocols[_]
}

is_insecure_protocol_value(val) {
    insecure_protocol_string(val)
}

is_insecure_protocol_value(val) {
    val.ir_type == "Array"
    v := val.value[_]
    insecure_protocol_string(v)
}

is_true(val) {
    val.ir_type == "Boolean"
    val.value == true
} else {
    val.ir_type == "String"
    v := lower(val.value)
    v == true_strings[_]
} else {
    val.ir_type == "Integer"
    val.value == 1
}

is_false(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "String"
    v := lower(val.value)
    v == false_strings[_]
} else {
    val.ir_type == "Integer"
    val.value == 0
} else {
    val.ir_type == "Null"
} else {
    val.ir_type == "Undef"
}

integrity_attr_exists(node) {
    kvs := all_keyvalues(node)
    kv := kvs[_]
    contains_keyword(kv.name, integrity_keywords)
} else {
    kvs := all_keyvalues(node)
    kv := kvs[_]
    contains_keyword(kv.name, disable_keywords)
}

protocol_attr(kv) {
    contains_keyword(kv.name, protocol_keywords)
}

integrity_disabled_attr(kv) {
    contains_keyword(kv.name, integrity_keywords)
    is_false(kv.value)
} else {
    contains_keyword(kv.name, disable_keywords)
    is_true(kv.value)
}

has_transfer_context(node) {
    contains_keyword(node.type, transfer_keywords)
} else {
    kvs := all_keyvalues(node)
    kv := kvs[_]
    contains_keyword(kv.name, transfer_keywords)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    kvs := all_keyvalues(node)
    kv := kvs[_]
    protocol_attr(kv)
    is_insecure_protocol_value(kv.value)
    not integrity_attr_exists(node)

    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Use of insecure protocol without integrity protection - enable TLS/DTLS or message authentication. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    kvs := all_keyvalues(node)
    kv := kvs[_]
    integrity_disabled_attr(kv)

    result := {
        "type": "sec_no_int_check",
        "element": kv,
        "path": parent.path,
        "description": "Integrity verification or checksum explicitly disabled - enable integrity checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    has_transfer_context(node)
    not integrity_attr_exists(node)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Data transfer or replication configured without integrity validation - enforce checksum or signature verification. (CWE-353)"
    }
}