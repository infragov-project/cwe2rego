package glitch

import data.glitch_lib

data_transmission_names := {"url", "source", "endpoint", "baseurl", "mirrorlist", "uri", "address", "location"}
encryption_names := {"validate_certs", "ssl", "tls", "verify_tls", "enable_ssl", "use_tls"}
integrity_names := {"gpgcheck", "repo_gpgcheck", "sslverify", "pkg_verify", "checksum", "verify_checksum", "integrity_check"}
storage_names := {"versioning", "server_side_encryption", "enable_versioning", "encryption_at_rest"}
firewall_names := {"ingress_rule", "egress_rule", "security_group_rule", "firewall_rule", "port"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in data_transmission_names
    glitch_lib.traverse(attr.value, "(?i)^http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure HTTP protocol used instead of HTTPS. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in encryption_names
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "SSL/TLS encryption disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in encryption_names
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|off|0)$", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "SSL/TLS encryption disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in integrity_names
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity check disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in integrity_names
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity check disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in integrity_names
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|off|0)$", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity check disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in storage_names
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Storage integrity features disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in storage_names
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|off|0)$", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Storage integrity features disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "AtomicUnit"
    node.type in {"shell", "command", "script"}
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"command", "script", "inline", "code", "shell"}
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr.value, "(?i)\\b(curl|wget|rsync|scp|ftp|tftp)\\b")
    not glitch_lib.traverse(attr.value, "(?i)(--checksum|--secure|--tls|https://)")
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Data transfer command without integrity validation. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in firewall_names
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr.value, "(?i)\\b(ftp|http|tftp|telnet)\\b")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Firewall rule allows insecure plaintext protocols. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    v := variables[_]
    glitch_lib.traverse(v.value, "(?i)^http://")
    result := {
        "type": "sec_no_int_check",
        "element": v,
        "path": parent.path,
        "description": "Variable uses insecure HTTP protocol. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "AtomicUnit"
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    glitch_lib.traverse(attr.value, "(?i)^http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Remote file source uses insecure HTTP protocol. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "AtomicUnit"
    node.type == "get_url"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "url"
    glitch_lib.traverse(attr.value, "(?i)^http://")
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "get_url resource uses insecure HTTP protocol. (CWE-353)"
    }
}