package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == data.security.protocol_attributes[_]
    
    attr.value.ir_type == "String"
    is_cleartext_protocol(attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Avoid using cleartext protocols for transmitting sensitive data. (CWE-319)"
    }
}

is_cleartext_protocol(protocol) {
    lower_protocol := lower(protocol)
    startswith(lower_protocol, "http://")
} else {
    lower_protocol := lower(protocol)
    lower_protocol == "http"
} else {
    lower_protocol := lower(protocol)
    lower_protocol == "telnet"
} else {
    lower_protocol := lower(protocol)
    lower_protocol == "ftp"
} else {
    lower_protocol := lower(protocol)
    lower_protocol == "smtp"
} else {
    lower_protocol := lower(protocol)
    startswith(lower_protocol, "ftp://")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == data.security.encryption_attributes[_]
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption must be enabled for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for explicit enablement of cleartext/ disables of TLS/SSL
    attr.name == data.security.tls_attributes[_]
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS/SSL must be enabled for secure communication. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for URL/endpoint attributes with cleartext protocols
    attr.name == data.security.endpoint_attributes[_]
    
    contains_cleartext_url(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Endpoint configured with insecure cleartext protocol. (CWE-319)"
    }
}

contains_cleartext_url(value) {
    value.ir_type == "String"
    is_cleartext_protocol(value.value)
} else {
    value.ir_type == "Array"
    arr_val := value.value[_]
    arr_val.ir_type == "String"
    is_cleartext_protocol(arr_val.value)
}