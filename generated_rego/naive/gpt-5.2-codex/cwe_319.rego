package glitch

import data.glitch_lib

insecure_protocol_regex := "(?i)^(http|ftp|telnet|smtp|pop3|imap|ldap|ws|amqp|nfs|smb|tcp)$"
insecure_scheme_regex := "(?i)^(http|ftp|ldap|smtp|ws|amqp|telnet|pop3|imap)://"
false_regex := "(?i)^(false|disabled|none|off|0)$"
true_regex := "(?i)^(true|enabled|on|1|yes)$"

protocol_fields := {"protocol","scheme","transport","listener_protocol","endpoint_type"}
tls_disable_fields := {"enable_tls","enable_ssl","https_only","require_tls","require_ssl","secure_transfer","force_https","encrypted_in_transit","transport_encryption","in_transit_encryption"}
endpoint_fields := {"url","uri","endpoint","connection_string","server"}
cert_fields := {"certificate","tls_certificate","ssl_certificate","keystore","certificate_arn","ssl_policy","tls_policy"}
port_fields := {"port","from_port","to_port","listener_port"}
allow_insecure_fields := {"allow_insecure","allow_unencrypted","allow_plaintext","insecure_transport","disable_encryption","plaintext"}
insecure_ports := {80,21,23,25,110,143,389,445,8080}

keyvalues(parent) = kvs {
    attrs := glitch_lib.all_attributes(parent)
    vars := glitch_lib.all_variables(parent)
    kvs := attrs | vars
}

name_matches(name, fields) {
    f := fields[_]
    glitch_lib.contains(name, f)
}

is_false_value(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "String"
    regex.match(false_regex, val.value)
} else {
    val.ir_type == "Integer"
    val.value == 0
}

is_true_value(val) {
    val.ir_type == "Boolean"
    val.value == true
} else {
    val.ir_type == "String"
    regex.match(true_regex, val.value)
} else {
    val.ir_type == "Integer"
    val.value == 1
}

is_empty_or_null(val) {
    val.ir_type == "Null"
} else {
    val.ir_type == "Undef"
} else {
    val.ir_type == "String"
    regex.match("(?i)^\\s*(null|none)?\\s*$", val.value)
}

has_insecure_protocol(val) {
    [_, n] := walk(val)
    n.ir_type == "String"
    regex.match(insecure_protocol_regex, n.value)
}

has_insecure_scheme(val) {
    [_, n] := walk(val)
    n.ir_type == "String"
    regex.match(insecure_scheme_regex, n.value)
}

has_insecure_port(val) {
    [_, n] := walk(val)
    n.ir_type == "Integer"
    port := insecure_ports[_]
    n.value == port
} else {
    [_, n] := walk(val)
    n.ir_type == "String"
    regex.match("^[0-9]+$", n.value)
    port := insecure_ports[_]
    to_number(n.value) == port
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := keyvalues(parent)
    kv := kvs[_]
    name_matches(kv.name, protocol_fields)
    has_insecure_protocol(kv.value)
    result := {
        "type": "sec_https",
        "element": kv,
        "path": parent.path,
        "description": "Insecure or cleartext protocol configured - Non-TLS protocols may transmit sensitive data in cleartext. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := keyvalues(parent)
    kv := kvs[_]
    name_matches(kv.name, tls_disable_fields)
    is_false_value(kv.value)
    result := {
        "type": "sec_https",
        "element": kv,
        "path": parent.path,
        "description": "TLS/SSL/HTTPS disabled or not enforced - Encryption in transit is not required. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := keyvalues(parent)
    kv := kvs[_]
    name_matches(kv.name, endpoint_fields)
    has_insecure_scheme(kv.value)
    result := {
        "type": "sec_https",
        "element": kv,
        "path": parent.path,
        "description": "Cleartext endpoint or connection string detected - Insecure scheme used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := keyvalues(parent)
    kv := kvs[_]
    name_matches(kv.name, cert_fields)
    is_empty_or_null(kv.value)
    result := {
        "type": "sec_https",
        "element": kv,
        "path": parent.path,
        "description": "Missing or empty TLS/SSL certificate configuration - Service may expose unencrypted traffic. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := keyvalues(parent)
    kv := kvs[_]
    name_matches(kv.name, port_fields)
    has_insecure_port(kv.value)
    result := {
        "type": "sec_https",
        "element": kv,
        "path": parent.path,
        "description": "Plaintext port exposed - Port commonly associated with cleartext protocols is open. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := keyvalues(parent)
    kv := kvs[_]
    name_matches(kv.name, allow_insecure_fields)
    is_true_value(kv.value)
    result := {
        "type": "sec_https",
        "element": kv,
        "path": parent.path,
        "description": "Explicit allowance of insecure or plaintext transport - Insecure traffic is permitted. (CWE-319)"
    }
}