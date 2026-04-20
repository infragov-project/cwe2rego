package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for insecure protocols in URLs
    attr.name == "url"
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|smtp://)", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used for data transmission without integrity checks"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for insecure protocols in sources
    attr.name == "source"
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|smtp://)", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used for data transmission without integrity checks"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for insecure protocols in baseurl
    attr.name == "baseurl"
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|smtp://)", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used for data transmission without integrity checks"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for insecure protocols in endpoint
    attr.name == "endpoint"
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|smtp://)", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used for data transmission without integrity checks"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for insecure protocols in api_endpoint
    attr.name == "api_endpoint"
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|smtp://)", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol (HTTP/FTP) used for data transmission without integrity checks"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled certificate validation
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    attr.value.value == "no"

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Certificate validation is disabled, allowing potential data tampering"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled certificate validation (boolean)
    attr.name == "validate_certs"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Certificate validation is disabled, allowing potential data tampering"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled GPG/Package signature verification
    attr.name == "gpgcheck"
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Package signature verification is disabled, allowing potential tampering"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for missing checksum in file downloads
    contains({"get_url", "remote_file", "cookbook_file", "file"}, node.type)
    attr.name == "checksum"
    attr.value.ir_type == "String"
    attr.value.value == ""

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing checksum for file download, allowing potential data corruption"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for missing checksum in file downloads (null)
    contains({"get_url", "remote_file", "cookbook_file", "file"}, node.type)
    attr.name == "checksum"
    attr.value.ir_type == "Null"

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing checksum for file download, allowing potential data corruption"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled data integrity verification
    attr.name == "verify_data_integrity"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Data integrity verification is disabled"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled checksum in file transfers
    attr.name == "disable_checksum"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Checksum verification is disabled for file transfers"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled SSL/TLS
    attr.name == "ssl"
    attr.value.ir_type == "String"
    attr.value.value == "disabled"

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "SSL/TLS is disabled, allowing insecure data transmission"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled SSL/TLS (boolean)
    attr.name == "ssl"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "SSL/TLS is disabled, allowing insecure data transmission"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for disabled integrity protection
    attr.name == "integrity_protection"
    attr.value.ir_type == "String"
    attr.value.value == "disabled"

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Integrity protection is disabled"
    }
}