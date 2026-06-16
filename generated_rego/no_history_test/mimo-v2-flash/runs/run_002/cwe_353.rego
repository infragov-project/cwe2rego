package glitch

import data.glitch_lib

insecure_url_pattern := "^(http|ftp)://"

url_attributes := {"url", "source", "baseurl", "mirrorlist", "uri", "link", "location", "remote_url", "download_url"}

integrity_attrs := {"checksum", "verify", "gpgcheck", "signature", "integrity_check", "hash_verification", "validate_certs", "encryption", "tls", "ssl", "https"}

check_insecure_url(value) {
    value.ir_type == "String"
    regex.match(insecure_url_pattern, value.value)
} else {
    value.ir_type == "Sum"
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match(insecure_url_pattern, node.value)
} else {
    value.ir_type == "VariableReference"
    true
} else {
    value.ir_type == "Array"
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match(insecure_url_pattern, node.value)
}

check_disabled_integrity(attr) {
    attr.name == "protocol"
    attr.value.ir_type == "String"
    attr.value.value == "http"
} else {
    attr.name == "disable_tls"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
} else {
    attr.name == "enable_ssl"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
} else {
    attr.name == "checksum"
    attr.value.ir_type == "String"
    attr.value.value == "disabled"
} else {
    attr.name == "hash_verification"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
} else {
    attr.name == "encryption"
    attr.value.ir_type == "String"
    attr.value.value == "disabled"
} else {
    attr.name == "signature_algorithm"
    attr.value.ir_type == "String"
    attr.value.value == "none"
} else {
    attr.name == "mutual_tls"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
} else {
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    attr.value.value == "no"
} else {
    attr.name == "validate_certs"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
} else {
    attr.name == "gpgcheck"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
} else {
    attr.name == "gpgcheck"
    attr.value.ir_type == "String"
    attr.value.value == "0"
} else {
    attr.name == "https"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

check_has_integrity(attrs) {
    attr := attrs[_]
    integrity_attrs[_] == attr.name
    attr.name != "validate_certs"
} else {
    attr := attrs[_]
    attr.name == "validate_certs"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
} else {
    attr := attrs[_]
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
} else {
    attr := attrs[_]
    attr.name == "https"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_disabled_integrity(attr)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check detected (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    url_attr := attrs[_]
    url_attributes[_] == url_attr.name
    check_insecure_url(url_attr.value)
    
    not check_has_integrity(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check for insecure URL (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    walk(var_node.value, [path, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key := entry.key.value
    value := entry.value
    attr := {"name": key, "value": value}
    check_disabled_integrity(attr)

    result := {
        "type": "sec_no_int_check",
        "element": value,
        "path": parent.path,
        "description": "Missing integrity check detected in variable (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    url_attr := attrs[_]
    url_attributes[_] == url_attr.name
    url_attr.value.ir_type == "VariableReference"
    
    not check_has_integrity(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check for URL from variable (CWE-353)"
    }
}