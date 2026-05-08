package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "telnet"}
url_attributes := {"url", "source", "baseurl", "endpoint", "uri", "mirrorlist", "src"}
integrity_attributes := {"validate_certs", "gpgcheck", "ssl_enabled", "tls_enabled", "secure", "checksum", "hash", "signature", "insecure"}

# Rule 1: Detect insecure protocols in AtomicUnit URL attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    url_attributes[attr.name]
    attr.value.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol detected in URL - Use encrypted protocols (HTTPS/FTPS) for data transmission to ensure integrity. (CWE-353)"
    }
}

# Rule 2: Detect insecure protocols in variables (Ansible vars)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    variable.value.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", variable.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": variable,
        "path": parent.path,
        "description": "Insecure protocol in variable - Use encrypted protocols (HTTPS/FTPS) for data transmission to ensure integrity. (CWE-353)"
    }
}

# Rule 3: Detect insecure protocols in hash values within variables (Ansible repo configs)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    variable.value.ir_type == "Hash"
    walk(variable.value, [path, node])
    node.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", node.value)
    result := {
        "type": "sec_no_int_check",
        "element": variable,
        "path": parent.path,
        "description": "Insecure protocol in configuration hash - Use encrypted protocols (HTTPS/FTPS) for data transmission to ensure integrity. (CWE-353)"
    }
}

# Rule 4: Detect disabled integrity flags in AtomicUnit attributes (String values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    integrity_attributes[attr.name]
    attr.value.ir_type == "String"
    val := lower(attr.value.value)
    val == "no"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity validation disabled - This compromises data integrity during transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    integrity_attributes[attr.name]
    attr.value.ir_type == "String"
    val := lower(attr.value.value)
    val == "false"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity validation disabled - This compromises data integrity during transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    integrity_attributes[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity validation disabled - This compromises data integrity during transmission. (CWE-353)"
    }
}

# Rule 5: Detect disabled integrity flags in variables (Ansible vars)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    integrity_attributes[key.value]
    value.ir_type == "String"
    val := lower(value.value)
    val == "no"
    result := {
        "type": "sec_no_int_check",
        "element": variable,
        "path": parent.path,
        "description": "Integrity validation disabled in configuration hash - This compromises data integrity during transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    integrity_attributes[key.value]
    value.ir_type == "String"
    val := lower(value.value)
    val == "false"
    result := {
        "type": "sec_no_int_check",
        "element": variable,
        "path": parent.path,
        "description": "Integrity validation disabled in configuration hash - This compromises data integrity during transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := parent.variables[_]
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    integrity_attributes[key.value]
    value.ir_type == "Integer"
    value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": variable,
        "path": parent.path,
        "description": "Integrity validation disabled in configuration hash - This compromises data integrity during transmission. (CWE-353)"
    }
}

# Rule 6: Detect insecure protocols in Chef remote_file source attribute
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    attr.value.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol in Chef remote_file source - Use encrypted protocols (HTTPS/FTPS) for data transmission to ensure integrity. (CWE-353)"
    }
}

# Rule 7: Detect insecure protocols in Chef remote_file source (Sum/concatenated strings)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    regex.match("^(http|ftp|telnet)://", n.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol in Chef remote_file source - Use encrypted protocols (HTTPS/FTPS) for data transmission to ensure integrity. (CWE-353)"
    }
}