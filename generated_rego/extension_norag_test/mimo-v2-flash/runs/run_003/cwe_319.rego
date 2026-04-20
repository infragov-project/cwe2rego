package glitch

import data.glitch_lib

insecure_protocol_pattern = "^(?i)(http|ftp|telnet|smtp)://"

encryption_control_attrs = {
    "validate_certs", "ssl_enabled", "use_tls", "require_ssl", "enforce_https",
    "secure_transfer_required", "use_ssl", "tls_enabled", "start_tls", "ssl_mode",
    "disable_ssl", "no_tls", "encryption_off", "secure_transfer_disabled"
}

disabled_values = {"no", "false", "disabled", "none"}

insecure_protocols = {"http", "ftp", "telnet", "smtp"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    url_attr_names = {"url", "endpoint_uri", "connection_string", "endpoint", "uri", "source"}
    url_attr_names[attr.name]
    
    attr.value.ir_type == "String"
    regex.match(insecure_protocol_pattern, attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol used in endpoint URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    
    var.value.ir_type == "String"
    regex.match(insecure_protocol_pattern, var.value.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    encryption_control_attrs[attr.name]
    
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption disabled by configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    encryption_control_attrs[attr.name]
    
    attr.value.ir_type == "String"
    attr.value.value == "no" or attr.value.value == "false" or attr.value.value == "disabled" or attr.value.value == "none"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption disabled by configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    attr.name == "protocol"
    attr.value.ir_type == "String"
    
    attr.value.value == "http" or attr.value.value == "ftp" or attr.value.value == "telnet" or attr.value.value == "smtp"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    
    port_attrs = [a | a := all_attrs[_]; a.name == "port"; 
                   (a.value.ir_type == "Integer" and a.value.value == 80) or 
                   (a.value.ir_type == "String" and a.value.value == "80")]
    
    count(port_attrs) > 0
    
    protocol_attrs = [a | a := all_attrs[_]; a.name == "protocol"; 
                     a.value.ir_type == "String"; 
                     (a.value.value == "tcp" or a.value.value == "TCP" or a.value.value == "http")]
    
    count(protocol_attrs) > 0
    
    result := {
        "type": "sec_https",
        "element": port_attrs[0],
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure network rule: open port 80 without encryption. (CWE-319)"
    }
}