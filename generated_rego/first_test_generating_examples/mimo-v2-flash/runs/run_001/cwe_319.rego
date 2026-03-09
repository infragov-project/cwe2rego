package glitch

import data.glitch_lib

# Rule 1: Detect explicit protocol attribute set to HTTP (Ansible)
# This specifically targets "protocol: HTTP" to avoid false positives on "port: 80"
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "protocol"
    attr.value.ir_type == "String"
    regex.match("(?i)^HTTP$", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol HTTP detected. (CWE-319)"
    }
}

# Rule 2: Detect health_check_protocol attribute set to HTTP (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "health_check_protocol"
    attr.value.ir_type == "String"
    regex.match("(?i)^HTTP$", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted health check protocol HTTP detected. (CWE-319)"
    }
}

# Rule 3: Detect plaintext passwords (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "password"
    attr.value.ir_type == "String"

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Plaintext password detected. (CWE-319)"
    }
}

# Rule 4: Detect unencrypted protocols in string values (http://, ftp://, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|telnet://|smtp://)", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol detected. (CWE-319)"
    }
}

# Rule 5: Detect Listen 80 in configuration content (Ansible lineinfile, Chef file content)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match("(?i)Listen 80", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Plaintext port configuration detected. (CWE-319)"
    }
}

# Rule 6: Detect VirtualHost *:80 in content attributes (Apache HTTP config)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("(?i)<VirtualHost \\*:80>", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted virtual host configuration detected. (CWE-319)"
    }
}

# Rule 7: Detect listen 80 in Nginx configuration content
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("(?i)listen\\s+80\\s", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted Nginx listen directive detected. (CWE-319)"
    }
}