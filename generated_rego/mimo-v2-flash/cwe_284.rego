package glitch

import data.glitch_lib

# Rule 1: Unrestricted network access in atomic attributes - CidrIp
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "CidrIp"
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0/0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 2: Unrestricted network access in atomic attributes - CidrIp (IPv6)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "CidrIp"
    attr.value.ir_type == "String"
    attr.value.value == "::/0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 3: Unrestricted network access in atomic attributes - source
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "source"
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0/0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 4: Unrestricted network access in atomic attributes - bind_addr (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "bind_addr"
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 5: Unrestricted network access in atomic attributes - vncserver_listen (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "vncserver_listen"
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 6: Unrestricted network access in variables - bind_addr (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    hash_pair.key.ir_type == "String"
    hash_pair.key.value == "bind_addr"
    hash_pair.value.ir_type == "String"
    hash_pair.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 7: Unrestricted network access in attributes - vncserver_listen (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "with_dict"
    attr.value.ir_type == "Hash"
    hash_pair := attr.value.value[_]
    hash_pair.key.ir_type == "String"
    hash_pair.key.value == "vncserver_listen"
    hash_pair.value.ir_type == "String"
    hash_pair.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network access - Open to world (CWE-284)"
    }
}

# Rule 8: Sensitive ports open to world - FromPort 22
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "FromPort"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 22
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 9: Sensitive ports open to world - FromPort 21
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "FromPort"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 21
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 10: Sensitive ports open to world - FromPort 3389
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "FromPort"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 3389
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 11: Sensitive ports open to world - ToPort 22
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "ToPort"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 22
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 12: Sensitive ports open to world - ToPort 21
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "ToPort"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 21
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 13: Sensitive ports open to world - ToPort 3389
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "ToPort"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 3389
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 14: Sensitive ports open to world - Port 22
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "Port"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 22
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 15: Sensitive ports open to world - Port 21
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "Port"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 21
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 16: Sensitive ports open to world - Port 3389
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    port_attr := attrs[_]
    
    port_attr.name == "Port"
    port_attr.value.ir_type == "Integer"
    port_attr.value.value == 3389
    
    cidr_attrs := [a | a := attrs[_]; a.name == "CidrIp"]
    count(cidr_attrs) > 0
    cidr_attrs[0].value.ir_type == "String"
    (cidr_attrs[0].value.value == "0.0.0.0/0" || cidr_attrs[0].value.value == "::/0" || cidr_attrs[0].value.value == "0.0.0.0")
    
    result := {
        "type": "sec_invalid_bind",
        "element": port_attr,
        "path": parent.path,
        "description": "Sensitive port open to world - Improper Access Control (CWE-284)"
    }
}

# Rule 17: Wildcards in IAM policy - Principal
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Principal"
    attr.value.ir_type == "String"
    attr.value.value == "*"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard in IAM policy - Improper Access Control (CWE-284)"
    }
}

# Rule 18: Wildcards in IAM policy - Action
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Action"
    attr.value.ir_type == "String"
    attr.value.value == "*"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard in IAM policy - Improper Access Control (CWE-284)"
    }
}

# Rule 19: Wildcards in IAM policy - Resource
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Resource"
    attr.value.ir_type == "String"
    attr.value.value == "*"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard in IAM policy - Improper Access Control (CWE-284)"
    }
}

# Rule 20: Public access flags - PublicRead Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PublicRead"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 21: Public access flags - PublicRead String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PublicRead"
    attr.value.ir_type == "String"
    attr.value.value == "true"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 22: Public access flags - PublicAccess Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PublicAccess"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 23: Public access flags - PublicAccess String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PublicAccess"
    attr.value.ir_type == "String"
    attr.value.value == "true"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 24: Public access flags - PubliclyReadable Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PubliclyReadable"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 25: Public access flags - PubliclyReadable String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PubliclyReadable"
    attr.value.ir_type == "String"
    attr.value.value == "true"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 26: Public access flags - PubliclyWritable Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PubliclyWritable"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 27: Public access flags - PubliclyWritable String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "PubliclyWritable"
    attr.value.ir_type == "String"
    attr.value.value == "true"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Public access enabled - Improper Access Control (CWE-284)"
    }
}

# Rule 28: Disabled authentication - AuthenticationType NONE
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "AuthenticationType"
    attr.value.ir_type == "String"
    attr.value.value == "NONE"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Improper Access Control (CWE-284)"
    }
}

# Rule 29: Disabled authentication - AuthenticationType Disabled
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "AuthenticationType"
    attr.value.ir_type == "String"
    attr.value.value == "Disabled"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Improper Access Control (CWE-284)"
    }
}

# Rule 30: Disabled authentication - SslEnforcement Disabled
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "SslEnforcement"
    attr.value.ir_type == "String"
    attr.value.value == "Disabled"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Improper Access Control (CWE-284)"
    }
}

# Rule 31: Disabled authentication - SslEnforcement false
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "SslEnforcement"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Improper Access Control (CWE-284)"
    }
}

# Rule 32: Disabled authentication - UseSSL false
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "UseSSL"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Authentication disabled - Improper Access Control (CWE-284)"
    }
}

# Rule 33: Overly permissive file modes - mode String 0777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "mode"
    attr.value.ir_type == "String"
    attr.value.value == "0777"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 34: Overly permissive file modes - mode String 777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "mode"
    attr.value.ir_type == "String"
    attr.value.value == "777"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 35: Overly permissive file modes - mode Integer 777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "mode"
    attr.value.ir_type == "Integer"
    attr.value.value == 777
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 36: Overly permissive file modes - permissions String 0777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "permissions"
    attr.value.ir_type == "String"
    attr.value.value == "0777"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 37: Overly permissive file modes - permissions String 777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "permissions"
    attr.value.ir_type == "String"
    attr.value.value == "777"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 38: Overly permissive file modes - permissions Integer 777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "permissions"
    attr.value.ir_type == "Integer"
    attr.value.value == 777
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 39: Overly permissive file modes - file_mode String 0777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "file_mode"
    attr.value.ir_type == "String"
    attr.value.value == "0777"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 40: Overly permissive file modes - file_mode String 777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "file_mode"
    attr.value.ir_type == "String"
    attr.value.value == "777"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 41: Overly permissive file modes - file_mode Integer 777
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "file_mode"
    attr.value.ir_type == "Integer"
    attr.value.value == 777
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive file permissions - Improper Access Control (CWE-284)"
    }
}

# Rule 42: World writable flag
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "WorldWritable"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "World writable resource - Improper Access Control (CWE-284)"
    }
}

# Rule 43: Unrestricted role assumption - String principal
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    action_attr := [a | a := attrs[_]; a.name == "Action"]
    principal_attr := [a | a := attrs[_]; a.name == "Principal"]
    count(action_attr) > 0
    count(principal_attr) > 0
    
    action_attr[0].value.ir_type == "String"
    contains(action_attr[0].value.value, "sts:AssumeRole")
    
    principal_attr[0].value.ir_type == "String"
    principal_attr[0].value.value == "*"
    
    result := {
        "type": "sec_invalid_bind",
        "element": principal_attr[0],
        "path": parent.path,
        "description": "Unrestricted role assumption - Improper Access Control (CWE-284)"
    }
}

# Rule 44: Unrestricted role assumption - Array principal
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    
    action_attr := [a | a := attrs[_]; a.name == "Action"]
    principal_attr := [a | a := attrs[_]; a.name == "Principal"]
    count(action_attr) > 0
    count(principal_attr) > 0
    
    action_attr[0].value.ir_type == "String"
    contains(action_attr[0].value.value, "sts:AssumeRole")
    
    principal_attr[0].value.ir_type == "Array"
    principal_value := principal_attr[0].value.value
    count(principal_value) > 0
    principal_value[0].ir_type == "String"
    principal_value[0].value == "*"
    
    result := {
        "type": "sec_invalid_bind",
        "element": principal_attr[0],
        "path": parent.path,
        "description": "Unrestricted role assumption - Improper Access Control (CWE-284)"
    }
}

# Rule 45: Disabled logging - Logging String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Logging"
    attr.value.ir_type == "String"
    attr.value.value == "Disabled"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Logging disabled - Missing audit controls (CWE-284)"
    }
}

# Rule 46: Disabled logging - Logging Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Logging"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Logging disabled - Missing audit controls (CWE-284)"
    }
}

# Rule 47: Disabled logging - EnableLogging String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "EnableLogging"
    attr.value.ir_type == "String"
    attr.value.value == "Disabled"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Logging disabled - Missing audit controls (CWE-284)"
    }
}

# Rule 48: Disabled logging - EnableLogging Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "EnableLogging"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Logging disabled - Missing audit controls (CWE-284)"
    }
}

# Rule 49: Disabled logging - LogEnabled String
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "LogEnabled"
    attr.value.ir_type == "String"
    attr.value.value == "Disabled"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Logging disabled - Missing audit controls (CWE-284)"
    }
}

# Rule 50: Disabled logging - LogEnabled Boolean
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "LogEnabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Logging disabled - Missing audit controls (CWE-284)"
    }
}