package glitch

import data.glitch_lib

insecure_protocols = {"http://", "ftp://", "telnet://", "smtp://", "tcp://", "udp://", "ws://", "plaintext", "unencrypted"}

encryption_flag_names = {"ssl", "tls", "encryption", "https_only", "secure_transfer", "enforce_ssl", "require_ssl", "enable_https_traffic_only", "use_ssl", "start_tls", "ssl_skip_verify", "validate_certs", "tlsAuth", "tlsAuthWithCACert", "ssl_mode"}

disabling_values = {"no", "false", "off", "disabled"}

contains_insecure_protocol(str) {
    contains(str, insecure_protocols[_])
}

contains_encryption_flag(name) {
    contains(name, encryption_flag_names[_])
}

is_disabling_value(value) {
    value.ir_type == "String"
    value.value == disabling_values[_]
} else {
    value.ir_type == "Boolean"
    value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    not contains(path, "comments")
    contains_insecure_protocol(node.value)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Using unencrypted network protocols in IaC configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_encryption_flag(var.name)
    is_disabling_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption flag explicitly disabled in IaC variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_encryption_flag(attr.name)
    is_disabling_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption flag explicitly disabled in IaC configuration. (CWE-319)"
    }
}