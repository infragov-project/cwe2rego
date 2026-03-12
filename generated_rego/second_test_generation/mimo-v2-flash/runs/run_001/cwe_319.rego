package glitch

import data.glitch_lib

insecure_protocols := {"http://", "ftp://", "telnet://", "smtp://"}
content_attributes := {"content", "config", "settings", "data", "body", "template"}
encryption_flags := {"enable_https_traffic_only", "ssl_enforcement", "require_ssl", "encryption_enabled", "tls_enforcement"}
sensitive_keywords := {"password", "secret", "key", "token", "api_key", "secret_key", "access_key", "auth_token"}
insecure_ports := {21, 23, 80, 8080}
port_patterns := {"port", "ports", "ingress", "egress", "allowed_port", "port_range"}
backup_patterns := {"backup", "export", "destination", "url", "endpoint"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    content_attributes[attr.name]
    walk(attr.value, [_, node])
    node.ir_type == "String"
    protocol := insecure_protocols[_]
    contains(node.value, protocol)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol detected in content - Use HTTPS or encrypted alternatives. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_flags[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Enable encryption for data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_flags[attr.name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "disabled"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Enable encryption for data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_flags[attr.name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "false"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Enable encryption for data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_flags[attr.name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "no"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Enable encryption for data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_flags[attr.name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "off"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Enable encryption for data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    sensitive_keywords[attr.name]
    attr.value.ir_type == "String"
    attr.value.value != ""
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Plaintext secret - Use a secret manager. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    sensitive_keywords[var.name]
    var.value.ir_type == "String"
    var.value.value != ""
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Plaintext secret in variable - Use a secret manager. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    port_patterns[attr.name]
    attr.value.ir_type == "Integer"
    insecure_ports[attr.value.value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure port configured - Avoid using ports for insecure protocols. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    port_patterns[attr.name]
    attr.value.ir_type == "String"
    port_num := to_number(attr.value.value)
    insecure_ports[port_num]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure port configured - Avoid using ports for insecure protocols. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    backup_patterns[attr.name]
    attr.value.ir_type == "String"
    contains(attr.value.value, "http://")
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Backup uses cleartext protocol - Use HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    content_attributes[attr.name]
    walk(attr.value, [_, node])
    node.ir_type == "String"
    contains(node.value, "password")
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Plaintext secret in content - Use a secret manager. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    content_attributes[attr.name]
    walk(attr.value, [_, node])
    node.ir_type == "String"
    contains(node.value, "sslmode_option")
    contains(node.value, "disable")
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "SSL disabled in content - Enable encryption for data in transit. (CWE-319)"
    }
}