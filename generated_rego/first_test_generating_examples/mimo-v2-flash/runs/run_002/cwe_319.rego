package glitch

import data.glitch_lib

# Rule 1: Detect insecure protocol usage in endpoints/URLs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "url"
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|telnet://)", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information (CWE-319): Insecure protocol used in endpoint/URL"
    }
}

# Rule 2: Detect hardcoded passwords in cleartext HTTP requests (Ansible uri module)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "ansible.builtin.uri"
    
    attrs := glitch_lib.all_attributes(node)
    
    # Find URL attribute to verify HTTP protocol
    url_attr := attrs[_]
    url_attr.name == "url"
    url_attr.value.ir_type == "String"
    regex.match("^(http://|ftp://|telnet://)", url_attr.value.value)
    
    # Find body attribute containing password
    body_attr := attrs[_]
    body_attr.name == "body"
    body_attr.value.ir_type == "Hash"
    
    # Check for password field in the body hash
    some k
    kv := body_attr.value.value[k]
    kv.key.ir_type == "String"
    kv.key.value == "password"
    kv.value.ir_type == "String"
    
    result := {
        "type": "sec_https",
        "element": body_attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information (CWE-319): Hardcoded password in cleartext HTTP request"
    }
}

# Rule 3: Detect insecure port 80 in firewall rules (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "port"
    attr.value.ir_type == "String"
    attr.value.value == "80"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information (CWE-319): Insecure port configuration allowing plaintext HTTP traffic"
    }
}

# Rule 4: Detect insecure port 80/tcp in firewall rules (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "port"
    attr.value.ir_type == "String"
    attr.value.value == "80/tcp"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information (CWE-319): Insecure port configuration allowing plaintext HTTP traffic"
    }
}

# Rule 5: Detect insecure server configurations in file content (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "file"
    
    attrs := glitch_lib.all_attributes(node)
    content_attr := attrs[_]
    content_attr.name == "content"
    content_attr.value.ir_type == "String"
    
    # Detect listen 80 or similar HTTP-only configurations
    regex.match("listen\\s+80", content_attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": content_attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information (CWE-319): Insecure server configuration listening on HTTP port 80"
    }
}