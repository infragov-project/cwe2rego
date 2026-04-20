package glitch

import data.glitch_lib

insecure_attr_names := {"validate_certs", "gpgcheck", "protocol", "disable_tls", "tls_enabled", "encryption", "checksum", "data_validation", "integrity_check", "enforce_https", "url", "source", "baseurl"}
insecure_values := {"no", "false", "disabled", "none", "off", 0}

check_insecure_url(value) {
    value.ir_type == "String"
    regex.match("^http://", value.value)
} else {
    value.ir_type == "Sum"
    regex.match("^http://", value.code)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == insecure_attr_names[_]
    (attr.value.ir_type == "String" or attr.value.ir_type == "Integer")
    attr.value.value == insecure_values[_]
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Insecure attribute detected. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"url", "source", "baseurl", "mirrorlist"}
    check_insecure_url(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - Insecure URL used. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    some pair in var.value.value
    pair.key.ir_type == "String"
    pair.key.value == insecure_attr_names[_]
    (pair.value.ir_type == "String" or pair.value.ir_type == "Integer")
    pair.value.value == insecure_values[_]
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing integrity check - Insecure attribute in variable detected. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    regex.match("^http://", var.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing integrity check - Insecure URL in variable detected. (CWE-353)"
    }
}