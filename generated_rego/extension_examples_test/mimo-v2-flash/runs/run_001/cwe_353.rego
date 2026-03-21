package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "telnet", "smtp", "udp"}
insecure_flag_names := {"validate_certs", "gpgcheck", "checksum", "integrity_check", "signing", "ssl", "tls", "encryption", "ssl_encryption"}
insecure_string_values := {"no", "false", "disabled", "none", "plaintext"}
url_attributes := {"url", "source", "baseurl", "mirrorlist"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure protocols in protocol attribute
    attr.name == "protocol"
    attr.value.ir_type == "String"
    insecure_protocols_value := attr.value.value
    insecure_protocols_value == insecure_protocols[_]
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol used without integrity checks (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for disabled security flags
    attr.name == insecure_flag_names[_]
    (attr.value.ir_type == "String" and attr.value.value in insecure_string_values) or
    (attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.value.ir_type == "Integer" and attr.value.value == 0)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Disabled security flag in data transmission (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for plaintext URLs in url or source attributes
    attr.name == url_attributes[_]
    attr.value.ir_type == "String"
    regex.match("^http://", attr.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Plaintext URL used without integrity checks (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    some kv in var.value.value
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    kv.key.value == "baseurl"
    regex.match("^http://", kv.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Insecure baseurl in variable configuration (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Hash"
    some kv in var.value.value
    kv.key.ir_type == "String"
    kv.key.value == insecure_flag_names[_]
    (kv.value.ir_type == "String" and kv.value.value in insecure_string_values) or
    (kv.value.ir_type == "Boolean" and kv.value.value == false) or
    (kv.value.ir_type == "Integer" and kv.value.value == 0)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Disabled security flag in variable configuration (CWE-353)"
    }
}