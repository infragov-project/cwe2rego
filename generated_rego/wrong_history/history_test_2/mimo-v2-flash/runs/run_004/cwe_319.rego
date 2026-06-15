package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure storage configurations
    attr.name in {"enable_https_traffic_only", "secure_transfer_required", "enforce_https"}
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Storage account configured to allow unencrypted HTTP traffic. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure load balancer protocols
    attr.name in {"protocol", "backend_protocol"}
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|tcp|ftp)$", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Load balancer using unencrypted protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    
    # Check for publicly accessible database without SSL
    has_public := false
    has_ssl_disabled := false
    
    attr := attrs[_]
    attr.name == "publicly_accessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    has_public := true
    
    attr2 := attrs[_]
    attr2.name in {"ssl_mode", "require_ssl"}
    attr2.value.ir_type in {"String", "Boolean"}
    (attr2.value.ir_type == "String" && attr2.value.value == "disabled") ||
    (attr2.value.ir_type == "Boolean" && attr2.value.value == false)
    has_ssl_disabled := true
    
    has_public
    has_ssl_disabled
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible database without SSL encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure compute instance metadata
    attr.name in {"http_tokens", "http_endpoint"}
    attr.value.ir_type == "String"
    regex.match("(?i)^(optional|enabled)$", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Compute instance allows unencrypted metadata service. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure firewall rules
    attr.name in {"protocol", "port"}
    attr.value.ir_type == "String"
    regex.match("(?i)^(tcp|ftp)$", attr.value.value) ||
    regex.match("(?i)^(80|21|23)$", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Firewall rule allows unencrypted protocols. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for missing HTTP to HTTPS redirection
    attr.name in {"redirect_http_to_https", "ssl_redirect"}
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "HTTP to HTTPS redirection is disabled. (CWE-319)"
    }
}