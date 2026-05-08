package glitch

import data.glitch_lib

# Rule for Ansible: Detect HTTP usage in URL attributes (CWE-353)
Glitch_Analysis[result] {
    # Gather parent unit blocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Gather all attributes within the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    # Only check attributes likely to contain URLs (e.g., 'url', 'source', 'baseurl')
    attr_names := {"url", "source", "baseurl", "mirrorlist", "dest"}
    lower_name := lower(attr.name)
    lower_name == attr_names[_]

    # Traverse the attribute value to find leaf nodes
    walk(attr.value, [_, leaf])

    # Check if the leaf node is a string containing an insecure protocol (HTTP, FTP, Telnet)
    leaf.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|telnet://)", leaf.value)

    # Exclude false positives where the URL is simply part of a comment or not the primary value
    # (This specific logic relies on the attribute name being a URL container)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol used in URL - Use HTTPS or other secure protocols to ensure data integrity. (CWE-353)"
    }
}

# Rule for Ansible: Detect disabled certificate validation (CWE-353)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    # Check for validate_certs attribute
    lower(attr.name) == "validate_certs"

    # Check if the value is explicitly false or "no"
    walk(attr.value, [_, leaf])
    leaf.ir_type == "String"
    regex.match("(?i)^(no|false)$", leaf.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Certificate validation disabled - Enable to verify integrity of connections. (CWE-353)"
    }
}

# Rule for Ansible/Chef/Puppet: Detect disabled GPG/checksum validation (CWE-353)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    # Check for GPG or checksum validation attributes
    lower_name := lower(attr.name)
    gpg_attrs := {"gpgcheck", "repo_gpgcheck"}
    lower_name == gpg_attrs[_]

    # Check if the value is 0 (disabled)
    walk(attr.value, [_, leaf])
    leaf.ir_type == "Integer"
    leaf.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Package integrity check (GPG) disabled - Enable to verify package authenticity. (CWE-353)"
    }
}