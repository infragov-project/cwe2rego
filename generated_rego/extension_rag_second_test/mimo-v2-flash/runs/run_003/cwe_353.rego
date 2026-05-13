package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    url_attr := attrs[_]
    url_attr.name == "url"
    
    url_value := url_attr.value
    url_value.ir_type == "String"
    regex.match("^(http|ftp)://", url_value.value)
    
    allowed_names := {"checksum", "md5", "sha256", "sha512", "signature", "integrity", "gpgcheck"}
    count({attr | attr := attrs[_]; allowed_names[attr.name]}) == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Download resource using insecure protocol without integrity check (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    repo_attr := attrs[_]
    repo_attr.name == "name"
    
    gpg_attr := attrs[_]
    gpg_attr.name == "gpgcheck"
    (gpg_attr.value.ir_type == "Integer" && gpg_attr.value.value == 0) || 
    (gpg_attr.value.ir_type == "Boolean" && gpg_attr.value.value == false)
    
    result := {
        "type": "sec_no_int_check",
        "element": gpg_attr,
        "path": parent.path,
        "description": "Repository configuration disables GPG check (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    variable.value.ir_type == "Hash"
    
    walk(variable.value, [path, n])
    n.ir_type == "Attribute"
    n.name == "gpgcheck"
    (n.value.ir_type == "Integer" && n.value.value == 0) || 
    (n.value.ir_type == "Boolean" && n.value.value == false)
    
    result := {
        "type": "sec_no_int_check",
        "element": n,
        "path": parent.path,
        "description": "Variable definition disables GPG check in repository configuration (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    download_types := {"get_url", "remote_file", "file", "win_get_url", "s3", "azure_blob"}
    node.type == download_types[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr_names := {attr.name | attr := attrs[_]}
    
    source_attrs := {"url", "source", "src", "source_location", "location"}
    count(attr_names & source_attrs) > 0
    
    integrity_attrs := {"checksum", "md5", "sha256", "sha512", "signature", "integrity", "gpgcheck"}
    count(attr_names & integrity_attrs) == 0
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Download resource without integrity verification (CWE-353)"
    }
}