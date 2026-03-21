package glitch

import data.glitch_lib

insecure_protocols = {"http", "ftp", "udp"}

insecure_ports = {80, 21, 23, 25, 110, 143}

insecure_tls_versions = {"1.0", "1.1", "ssl", "ssl2", "ssl3"}

disable_indicators = {"verify_ssl", "ssl_verify", "gpgcheck", "validate_certs", "verify_certificate", "check_certificate"}

disable_values = {false, "false", "False", "no", "off", "none", "", "null", 0}

insecure_auth_methods = {"basic", "plaintext", "clear", "anonymous", "none"}

contains_str(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}

check_url(value) {
    value.ir_type == "String"
    regex.match("^(http|ftp|udp)://", value.value)
}

check_disable_attr(attr) {
    contains_str(attr.name, "verify")
} {
    contains_str(attr.name, "gpgcheck")
} {
    contains_str(attr.name, "validate")
} {
    attr.value.ir_type == "String"
    attr.value.value in disable_values
} {
    attr.value.ir_type == "Boolean"
    attr.value.value in disable_values
} {
    attr.value.ir_type == "Integer"
    attr.value.value in disable_values
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "get_url"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "url"
    check_url(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol used in data transmission (HTTP/FTP/UDP). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    check_url(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol used in file download. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_disable_attr(attr)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity verification disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    check_url(var.value)
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Insecure protocol in variable. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    attrs := glitch_lib.all_attributes(var)
    attr := attrs[_]
    attr.name == "baseurl"
    check_url(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol in repository URL. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    attrs := glitch_lib.all_attributes(var)
    attr := attrs[_]
    check_disable_attr(attr)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity check disabled in repository configuration. (CWE-353)"
    }
}