package glitch

import data.glitch_lib

url_attributes := {"source", "url", "baseurl"}
protocol_attributes := {"protocol"}
boolean_attributes := {"ssl", "validate_certs", "gpgcheck"}
integer_attributes := {"gpgcheck"}
security_attributes := {"security_policy", "encryption", "checksum"}

contains_insecure_protocol(value) {
    value.ir_type == "String"
    regex.match("(?i)http://|ftp://|udp://", value.value)
} else {
    value.ir_type == "VariableReference"
    # Cannot determine value, flag as potentially insecure
}

is_insecure_value(attr) {
    attr.name in url_attributes
    contains_insecure_protocol(attr.value)
}

is_insecure_value(attr) {
    attr.name in url_attributes
    attr.value.ir_type == "Sum"
    regex.match("(?i)http://|ftp://|udp://", attr.value.code)
}

is_insecure_value(attr) {
    attr.name in protocol_attributes
    attr.value.ir_type == "String"
    attr.value.value in {"http", "ftp", "udp"}
}

is_insecure_value(attr) {
    attr.name in boolean_attributes
    attr.value.ir_type == "Boolean"
    attr.value.value == false
} else {
    attr.name in boolean_attributes
    attr.value.ir_type == "String"
    attr.value.value in {"no", "false", "0"}
}

is_insecure_value(attr) {
    attr.name in integer_attributes
    attr.value.ir_type == "Integer"
    attr.value.value == 0
}

is_insecure_value(attr) {
    attr.name in security_attributes
    attr.value.ir_type == "String"
    attr.value.value in {"none", "permissive", "weak", "disabled", "false"}
} else {
    attr.name in security_attributes
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

find_insecure_attrs_in_hash(value) = attrs {
    attrs = {a |
        walk(value, [path, n])
        n.ir_type == "Hash"
        some i
        pair := n.value[i]
        key_expr := pair.key
        value_expr := pair.value
        key_expr.ir_type == "String"
        url_attributes[key_expr.value]
        is_insecure_value({"name": key_expr.value, "value": value_expr})
        a := {"name": key_expr.value, "value": value_expr, "ir_type": "Attribute", "line": key_expr.line, "code": key_expr.code}
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_insecure_value(attr)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check in transmission protocol - Use secure protocols like HTTPS with TLS enforcement. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    insecure_pairs := find_insecure_attrs_in_hash(var.value)
    pair := insecure_pairs[_]

    result := {
        "type": "sec_no_int_check",
        "element": pair,
        "path": parent.path,
        "description": "Missing support for integrity check in transmission protocol - Use secure protocols like HTTPS with TLS enforcement. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    code := node.code
    insecure_patterns := {
        "validate_certs:\\s*no",
        "validate_certs:\\s*false",
        "gpgcheck:\\s*0",
        "gpgcheck:\\s*false",
        "protocol:\\s*http",
        "protocol:\\s*ftp",
        "protocol:\\s*udp",
        "encryption:\\s*disabled",
        "encryption:\\s*none",
        "checksum:\\s*false",
        "security_policy:\\s*none",
        "security_policy:\\s*permissive",
        "security_policy:\\s*weak",
        "source\\s+\"http://",
        "source\\s+'http://",
        "url\\s+\"http://",
        "url\\s+'http://",
        "http%3A%2F%2F"
    }
    pattern := insecure_patterns[_]
    regex.match(pattern, code)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check in transmission protocol - Use secure protocols like HTTPS with TLS enforcement. (CWE-353)"
    }
}