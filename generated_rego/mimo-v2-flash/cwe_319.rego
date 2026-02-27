package glitch

import data.glitch_lib

# Keywords indicating cleartext transmission protocols
protocol_keywords := {"protocol", "scheme", "connection_protocol"}
# Risk values for cleartext protocols
protocol_risk_values := {"HTTP", "FTP", "Telnet", "SMTP", "TCP", "LDAP"}
# Keywords indicating encryption flags
encryption_keywords := {"ssl", "tls", "https_only", "encryption_enabled", "secure_transport"}
# Risk values for disabled encryption
encryption_risk_values := {"false", "disabled", "off", "none", "0"}
# Keywords for endpoints/URIs
endpoint_keywords := {"endpoint", "uri", "url", "host"}
# Keywords for insecure ports
port_keywords := {"port"}
# Risk port values
insecure_ports := {80, 21, 23, 389}
# Risk patterns for cleartext URI schemes
cleartext_schemes := {"http://", "ftp://", "telnet://"}

# Check for cleartext protocol in String values
check_string_protocol(value) {
    value.ir_type == "String"
    regex.match(sprintf("(?i)^(%s)$", [concat("|", protocol_risk_values)]), value.value)
}

# Check for cleartext scheme in String values
check_string_scheme(value) {
    value.ir_type == "String"
    cleartext_schemes[_] == value.value
}

# Check for cleartext protocol in Sum values (including nested Sums)
check_sum_protocol(sum, root) {
    sum.ir_type == "Sum"
    sum.left.ir_type == "String"
    check_string_protocol(sum.left)
} else {
    sum.ir_type == "Sum"
    sum.right.ir_type == "String"
    check_string_protocol(sum.right)
} else {
    sum.ir_type == "Sum"
    sum.left.ir_type == "Sum"
    check_sum_protocol(sum.left, root)
} else {
    sum.ir_type == "Sum"
    sum.right.ir_type == "Sum"
    check_sum_protocol(sum.right, root)
}

# Check for cleartext scheme in Sum values (including nested Sums)
check_sum_scheme(sum, root) {
    sum.ir_type == "Sum"
    sum.left.ir_type == "String"
    check_string_scheme(sum.left)
} else {
    sum.ir_type == "Sum"
    sum.right.ir_type == "String"
    check_string_scheme(sum.right)
} else {
    sum.ir_type == "Sum"
    sum.left.ir_type == "Sum"
    check_sum_scheme(sum.left, root)
} else {
    sum.ir_type == "Sum"
    sum.right.ir_type == "Sum"
    check_sum_scheme(sum.right, root)
}

# Check for disabled encryption in Attribute values
check_attr_encryption(attr, root) {
    attr.ir_type == "Attribute"
    encryption_keywords[attr.name]
    attr.value.ir_type == "String"
    encryption_risk_values[attr.value.value]
}

# Check for disabled encryption in Variable values
check_var_encryption(var, root) {
    var.ir_type == "Variable"
    encryption_keywords[var.name]
    var.value.ir_type == "String"
    encryption_risk_values[var.value.value]
}

# Check for insecure port in Attribute values
check_attr_port(attr, root) {
    attr.ir_type == "Attribute"
    port_keywords[attr.name]
    attr.value.ir_type == "Integer"
    insecure_ports[attr.value.value]
}

# Check for insecure port in Variable values
check_var_port(var, root) {
    var.ir_type == "Variable"
    port_keywords[var.name]
    var.value.ir_type == "Integer"
    insecure_ports[var.value.value]
}

# Rule for cleartext protocol detection in Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_keywords[attr.name]
    check_string_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission Protocol - Usage of unencrypted protocols (HTTP, FTP, Telnet, etc.) in communication channels. (CWE-319)"
    }
}

# Rule for cleartext protocol detection in Attributes with Sum
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_keywords[attr.name]
    check_sum_protocol(attr.value, parent)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission Protocol - Usage of unencrypted protocols (HTTP, FTP, Telnet, etc.) in communication channels. (CWE-319)"
    }
}

# Rule for cleartext protocol detection in Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    protocol_keywords[var.name]
    check_string_protocol(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission Protocol - Usage of unencrypted protocols (HTTP, FTP, Telnet, etc.) in communication channels. (CWE-319)"
    }
}

# Rule for cleartext protocol detection in Variables with Sum
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    protocol_keywords[var.name]
    check_sum_protocol(var.value, parent)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission Protocol - Usage of unencrypted protocols (HTTP, FTP, Telnet, etc.) in communication channels. (CWE-319)"
    }
}

# Rule for cleartext endpoint URI detection in Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    endpoint_keywords[attr.name]
    check_string_scheme(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Endpoint URI - Usage of cleartext protocols (http://, ftp://, telnet://) in endpoint URIs. (CWE-319)"
    }
}

# Rule for cleartext endpoint URI detection in Attributes with Sum
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    endpoint_keywords[attr.name]
    check_sum_scheme(attr.value, parent)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Endpoint URI - Usage of cleartext protocols (http://, ftp://, telnet://) in endpoint URIs. (CWE-319)"
    }
}

# Rule for cleartext endpoint URI detection in Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    endpoint_keywords[var.name]
    check_string_scheme(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Endpoint URI - Usage of cleartext protocols (http://, ftp://, telnet://) in endpoint URIs. (CWE-319)"
    }
}

# Rule for cleartext endpoint URI detection in Variables with Sum
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    endpoint_keywords[var.name]
    check_sum_scheme(var.value, parent)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Endpoint URI - Usage of cleartext protocols (http://, ftp://, telnet://) in endpoint URIs. (CWE-319)"
    }
}

# Rule for disabled encryption detection in Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_attr_encryption(attr, parent)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Disabled Encryption Flag - SSL/TLS or encryption flags are explicitly disabled (false, disabled, off). (CWE-319)"
    }
}

# Rule for disabled encryption detection in Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    check_var_encryption(var, parent)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Disabled Encryption Flag - SSL/TLS or encryption flags are explicitly disabled (false, disabled, off). (CWE-319)"
    }
}

# Rule for insecure port detection in Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_attr_port(attr, parent)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure Port Configuration - Usage of insecure ports (80, 21, 23, 389) for data transmission without encryption. (CWE-319)"
    }
}

# Rule for insecure port detection in Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    check_var_port(var, parent)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Insecure Port Configuration - Usage of insecure ports (80, 21, 23, 389) for data transmission without encryption. (CWE-319)"
    }
}