package glitch

import data.glitch_lib

protocol_pattern := "^(http|ftp|smtp|telnet)://"

encryption_attributes := {
    "ssl", "tls", "encryption_in_transit", "require_ssl", "secure_transfer_required", 
    "validate_certs", "ssl_enforcement_disabled", "ssl_mode", "use_ssl", "start_tls", 
    "tlsAuth", "tlsAuthWithCACert", "tlsSkipVerify", "enable_https_traffic_only", 
    "ssl_skip_verify", "verify_mode", "https", "encryption", "encrypt", "ssl_enabled", 
    "tls_enabled", "http_ssl", "ssl_verify", "tls_verify", "ssl_validation", "use_tls",
    "tls_enable", "ssl_enable", "enforce_ssl", "force_ssl", "require_tls", "enforce_tls"
}

insecure_values := {"false", "disable", "disabled", "0", "none", "no", "off", "disabled"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    glitch_lib.traverse(attr.value, protocol_pattern)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Insecure protocol used in attribute '%s' of atomic unit '%s' (CWE-319)", [attr.name, node.name.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    glitch_lib.traverse(var.value, protocol_pattern)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": sprintf("Insecure protocol used in variable '%s' (CWE-319)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    encryption_attributes[attr.name]
    
    walk(attr.value, [path, n])
    n.ir_type == "Boolean" or n.ir_type == "String"
    v := lower(n.value)
    insecure_values[v]
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Disabled encryption in attribute '%s' of atomic unit '%s' (CWE-319)", [attr.name, node.name.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    walk(var.value, [path, n])
    n.ir_type == "Boolean" or n.ir_type == "String"
    v := lower(n.value)
    insecure_values[v]
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": sprintf("Disabled encryption in variable '%s' (CWE-319)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"port", "ports", "dport", "src_port", "dest_port"}
    walk(attr.value, [path, n])
    n.ir_type == "Integer"
    n.value == 80
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Port 80 (HTTP) used in attribute '%s' of atomic unit '%s' (CWE-319)", [attr.name, node.name.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in {"source", "url", "uri", "endpoint", "base_url", "api_url", "service_url"}
    glitch_lib.traverse(attr.value, protocol_pattern)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Insecure protocol in endpoint attribute '%s' of atomic unit '%s' (CWE-319)", [attr.name, node.name.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    walk(attr.value, [path, n])
    n.ir_type == "String"
    contains(lower(n.value), "http://")
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": sprintf("HTTP URI found in attribute '%s' of atomic unit '%s' (CWE-319)", [attr.name, node.name.value])
    }
}