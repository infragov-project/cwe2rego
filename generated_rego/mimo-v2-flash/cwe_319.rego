package glitch

import data.glitch_lib

insecure_protocols := {"http://", "ftp://", "telnet://", "smtp://", "tcp://", "udp://"}

insecure_keywords := {"insecure", "plaintext", "unauthenticated", "no_encryption", "disable_https", "disabled", "false", "allow_unencrypted", "non_ssl"}

encryption_flags := {"ssl_enabled", "tls_disabled", "https_only", "allow_unencrypted", "ssl_enforcement", "tls_policy", "secure_connection_required", "require_ssl", "tls_enforcement", "secure_transfer"}

has_insecure_protocol(expr) {
    walk(expr, [_, node])
    node.ir_type == "String"
    some i
    protocol := insecure_protocols[i]
    contains(lower(node.value), protocol)
}

has_insecure_keyword(expr) {
    walk(expr, [_, node])
    node.ir_type == "String"
    some i
    keyword := insecure_keywords[i]
    contains(lower(node.value), keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    has_insecure_protocol(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Variable contains insecure protocol URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Sum"
    has_insecure_protocol(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Variable contains insecure protocol in concatenation. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    has_insecure_keyword(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Variable contains insecure keyword. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "String"
    has_insecure_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Attribute contains insecure protocol URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "Sum"
    has_insecure_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Attribute contains insecure protocol in concatenation. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    has_insecure_keyword(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Attribute contains insecure keyword. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    lower(attr.name) == encryption_flags[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    lower(attr.name) == encryption_flags[_]
    attr.value.ir_type == "String"
    attr.value.value == "false"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption flag set to 'false'. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "file_line"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "line"
    has_insecure_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "File line contains insecure protocol URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "uri"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "url"
    has_insecure_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "URI task uses insecure protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "azurerm_storage_account"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enable_https_traffic_only"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Storage account configured without HTTPS-only traffic. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "aws_db_instance"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "ssl_mode"
    attr.value.ir_type == "String"
    attr.value.value == "disabled"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Database instance has SSL/TLS disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "aws_db_instance"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "ssl_mode"
    attr.value.ir_type == "String"
    attr.value.value == "allow_non_ssl"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Database instance allows non-SSL connections. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "aws_lb_listener"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol"
    attr.value.ir_type == "String"
    attr.value.value == "http"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Load balancer listener using HTTP. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "aws_lb_listener"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol"
    attr.value.ir_type == "String"
    attr.value.value == "ftp"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Load balancer listener using FTP. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "aws_api_gateway_rest_api"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol_type"
    attr.value.ir_type == "String"
    attr.value.value == "http"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "API Gateway configured with HTTP instead of HTTPS. (CWE-319)"
    }
}