package glitch

import data.glitch_lib

integrity_keywords := {"checksum", "validation", "verify", "integrity", "hash", "mac", "validate_certs", "gpgcheck"}
insecure_protocols := {"http", "ftp", "smtp", "plaintext"}
disabled_values_pattern := "(?i)(false|no|off|disabled|0)"

integrity_pattern := sprintf("(?i)(%s)", [concat("|", integrity_keywords)])
insecure_pattern := sprintf("(?i)(%s)", [concat("|", insecure_protocols)])

is_disabled_value(value) {
    value.ir_type == "String"
    regex.match(disabled_values_pattern, value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    value.ir_type == "Boolean"
    value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    walk(var.value, [path, n])
    n.ir_type == "Hash"
    pair := n.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    regex.match(integrity_pattern, key.value)
    is_disabled_value(value)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing integrity validation in data transfer - Integrity check is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    insecure_by_code := regex.match(insecure_pattern, node.code)
    matching_attrs := {attr | attr := glitch_lib.all_attributes(node)[_]; attr.value.ir_type == "String"; regex.match(insecure_pattern, attr.value.value)}
    insecure_by_attr := count(matching_attrs) > 0
    
    insecure_by_code == true
    insecure_by_attr == true
    
    attrs := glitch_lib.all_attributes(node)
    integrity_attrs := {a | a := attrs[_]; regex.match(integrity_pattern, a.name.value)}
    count(integrity_attrs) == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check in network communication - Insecure protocol used without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    integrity_attr := attrs[_]
    regex.match(integrity_pattern, integrity_attr.name.value)
    is_disabled_value(integrity_attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": integrity_attr,
        "path": parent.path,
        "description": "Integrity check explicitly disabled - Integrity validation is turned off. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    download_pattern := "(?i)(remote_file|get_url|url|source|download)"
    is_download_type := regex.match(download_pattern, node.type)
    is_download_code := regex.match(download_pattern, node.code)
    
    attrs := glitch_lib.all_attributes(node)
    source_attr := {a | a := attrs[_]; regex.match("(?i)(source|url)", a.name.value)}
    count(source_attr) > 0
    source := source_attr[_]
    source.value.ir_type == "String"
    regex.match(insecure_pattern, source.value.value)
    
    integrity_attrs := {a | a := attrs[_]; regex.match(integrity_pattern, a.name.value)}
    count(integrity_attrs) == 0
    
    any([is_download_type, is_download_code])
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Download from insecure source without integrity validation - Data transfer lacks checksum validation. (CWE-353)"
    }
}