package glitch

import data.glitch_lib
import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)protocol", attr.name)
    attr.value.ir_type == "String"
    regex.match("^(http|ftp|telnet|smtp)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission using unencrypted protocol - Avoid using unencrypted protocols like HTTP, FTP, etc. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)endpoint|url|uri|source|location", attr.name)
    glitch_lib.traverse(attr.value, ".*http://.*")
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission using HTTP endpoint - Avoid using unencrypted endpoints. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)enable_https_traffic_only|secure_transfer_required|ssl_enforcement", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Misconfigured encryption setting - Encryption is disabled or not enforced. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)enable_https_traffic_only|secure_transfer_required|ssl_enforcement", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)disabled|false", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Misconfigured encryption setting - Encryption is disabled or not enforced. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    glitch_lib.traverse(var.value, ".*http://.*")
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission in variable - Variable contains HTTP URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    regex.match("(?i)validate_certs|verify_ssl|check_ssl", n.name)
    n.value.ir_type == "String"
    regex.match("^(no|false|disabled)$", n.value.value)
    result := {
        "type": "sec_https",
        "element": n,
        "path": parent.path,
        "description": "Insecure certificate validation - Certificate validation is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    regex.match("(?i)protocol", kv.key.value)
    kv.value.ir_type == "String"
    regex.match("^(http|ftp|telnet|smtp)$", kv.value.value)
    result := {
        "type": "sec_https",
        "element": kv.value,
        "path": parent.path,
        "description": "Cleartext transmission using unencrypted protocol - Avoid using unencrypted protocols like HTTP, FTP, etc. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    regex.match("(?i)endpoint|url|uri|source|location", kv.key.value)
    glitch_lib.traverse(kv.value, ".*http://.*")
    result := {
        "type": "sec_https",
        "element": kv.value,
        "path": parent.path,
        "description": "Cleartext transmission using HTTP endpoint - Avoid using unencrypted endpoints. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    regex.match("(?i)enable_https_traffic_only|secure_transfer_required|ssl_enforcement", kv.key.value)
    kv.value.ir_type == "Boolean"
    kv.value.value == false
    result := {
        "type": "sec_https",
        "element": kv.value,
        "path": parent.path,
        "description": "Misconfigured encryption setting - Encryption is disabled or not enforced. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    regex.match("(?i)enable_https_traffic_only|secure_transfer_required|ssl_enforcement", kv.key.value)
    kv.value.ir_type == "String"
    regex.match("(?i)disabled|false", kv.value.value)
    result := {
        "type": "sec_https",
        "element": kv.value,
        "path": parent.path,
        "description": "Misconfigured encryption setting - Encryption is disabled or not enforced. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    regex.match("(?i)validate_certs|verify_ssl|check_ssl", kv.key.value)
    kv.value.ir_type == "String"
    regex.match("^(no|false|disabled)$", kv.value.value)
    result := {
        "type": "sec_https",
        "element": kv.value,
        "path": parent.path,
        "description": "Insecure certificate validation - Certificate validation is disabled. (CWE-319)"
    }
}