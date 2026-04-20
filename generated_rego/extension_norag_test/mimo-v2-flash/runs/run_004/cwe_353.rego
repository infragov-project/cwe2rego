package glitch

import data.glitch_lib

url_attributes = {"url", "source", "baseurl", "mirrorlist", "dest", "endpoint", "api_protocol", "download_url", "uri", "path", "location", "base_url"}
security_attributes = {"validate_certs", "ssl_mode", "gpgcheck", "checksum", "encryption", "tls", "ssl", "use_ssl", "enable_tls", "validation", "integrity", "server_side_encryption", "encrypt_connections", "message_integrity", "verify_ssl", "verify_checksum", "check_checksum"}
insecure_ports = {80, 21, 23, 25}
disabled_values = {"disabled", "none", "no", "false", "0"}

# Check for insecure protocols (http:// or ftp://) in string values
contains_insecure_protocol(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i)(http://|ftp://)", n.value)
}

# Check for insecure protocol in any attribute value (recursively)
has_insecure_protocol_value(value) {
    contains_insecure_protocol(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    url_attributes[attr.name]
    has_insecure_protocol_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Unencrypted protocol in attribute '%s'", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    attr.name == "port"
    attr.value.ir_type == "Integer"
    insecure_ports[attr.value.value]
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Insecure port %d used", [attr.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    security_attributes[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Security feature '%s' disabled", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    security_attributes[attr.name]
    attr.value.ir_type == "String"
    disabled_values[attr.value.value]
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Security feature '%s' disabled", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    security_attributes[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Security feature '%s' disabled", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    has_insecure_protocol_value(var.value)
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": "Variable contains insecure protocol"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    security_attributes[attr.name]
    attr.value.ir_type == "FunctionCall"
    # Check if function call has disabled values in arguments
    some arg in attr.value.args
    arg.ir_type == "Integer"
    arg.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Security feature '%s' may be disabled", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    security_attributes[attr.name]
    attr.value.ir_type == "FunctionCall"
    # Check if function call has disabled string values in arguments
    some arg in attr.value.args
    arg.ir_type == "String"
    disabled_values[arg.value]
    result := {
        "type": "sec_no_int_check",
        "element": parent,
        "path": parent.path,
        "description": sprintf("Security feature '%s' may be disabled", [attr.name])
    }
}