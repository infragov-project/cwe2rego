package glitch

import data.glitch_lib

# Detect cleartext protocol usage in Variables (Ansible vars, Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|telnet://|smtp://|ws://)", var.value.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Usage of unencrypted protocol detected in variable. (CWE-319)"
    }
}

# Detect cleartext protocol usage in Atomic Unit Attributes (Ansible tasks, Chef resources)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|telnet://|smtp://|ws://)", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Usage of unencrypted protocol detected in IaC configuration. (CWE-319)"
    }
}

# Detect cleartext protocol usage in complex/nested content (Ansible content, Chef file content)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    walk(attr.value, [path, n])
    n.ir_type == "String"
    regex.match("(?i)(http://|ftp://)", n.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Usage of unencrypted protocol detected in IaC configuration. (CWE-319)"
    }
}

# Detect insecure port 80 in Attributes (e.g., port: 80)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "port"
    attr.value.ir_type == "Integer"
    attr.value.value == 80

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Usage of insecure HTTP port 80 detected. (CWE-319)"
    }
}

# Detect insecure ports in command strings (nginx listen, iptables dport)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match("(?i)\\blisten\\s+80\\b|\\b--dport\\s+(21|80)\\b", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure port detected in configuration/command. (CWE-319)"
    }
}

# Detect disabled encryption flags (Boolean)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "Boolean"
    attr.value.value == false
    regex.match("(?i)(https_only|ssl_enforcement|enable_https_traffic_only|force_https|require_ssl)", attr.name)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption flag explicitly disabled in IaC configuration. (CWE-319)"
    }
}

# Detect disabled encryption in config file content (e.g., ssl_enable=NO)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match("(?i)\\bssl_enable\\s*=\\s*NO\\b", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL explicitly disabled in configuration content. (CWE-319)"
    }
}