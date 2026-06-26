package glitch

import data.glitch_lib

insecure_url_pattern := "(?i)^(http|ftp|telnet|ldap|smtp)://"

encryption_flags := {
    "enable_https_traffic_only", "https_only", "require_secure_transfer",
    "enforce_https", "ssl_enabled", "tls_enabled", "ssl_enforcement_enabled",
    "require_secure_transport", "transit_encryption_enabled",
    "secure_transfer_required", "in_transit_encryption",
    "ssl_enforcement", "require_ssl", "ssl_mode"
}

protocol_fields := {"protocol", "scheme", "listener_protocol", "client_broker", "broker_protocol"}

port_fields := {"from_port", "to_port", "port", "destination_port", "source_port"}

insecure_ports := {21, 23, 25, 80, 110, 143, 389, 8000, 8080}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(insecure_url_pattern, attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol URL used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == encryption_flags[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption in transit explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == encryption_flags[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(disabled|false|off|none|0|no)$", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption in transit explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == protocol_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp|plaintext|rsh|rlogin)$", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure cleartext protocol declared. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == port_fields[_]
    attr.value.ir_type == "Integer"
    attr.value.value == insecure_ports[_]

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted port exposed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == port_fields[_]
    attr.value.ir_type == "String"
    port := to_number(attr.value.value)
    port == insecure_ports[_]

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted port exposed. (CWE-319)"
    }
}