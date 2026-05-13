package glitch

import data.glitch_lib

insecure_url_pattern = "^(http|ftp)://"
insecure_protocols = {"http", "ftp", "smtp", "tcp"}
encryption_attr_pattern = "(?i)(ssl|tls|https|encrypt|secure|validate_cert|enforce|require_|validate_certs)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_entries := var.value.value
    some i
    entry := hash_entries[i]
    entry.key.ir_type == "String"
    entry.key.value == "protocol"
    entry.value.ir_type == "String"
    protocol := entry.value.value
    insecure_protocols[protocol]
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol"
    attr.value.ir_type == "String"
    protocol := attr.value.value
    insecure_protocols[protocol]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(encryption_attr_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption explicitly disabled (boolean). (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(encryption_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    attr.value.value == "no"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption explicitly disabled (string). (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    glitch_lib.traverse(var.value, insecure_url_pattern)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure URL in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, insecure_url_pattern)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure URL in attribute. (CWE-319)"
    }
}