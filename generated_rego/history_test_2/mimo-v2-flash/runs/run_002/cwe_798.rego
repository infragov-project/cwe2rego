package glitch

import data.glitch_lib

sensitive_keywords := ["password", "secret", "token", "key", "apikey", "credential", "auth", "passwd", "private", "certificate"]

private_key_pattern := "-----BEGIN"

api_key_patterns := ["AKIA", "AIza", "ghp_"]

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_key_values := {kv | 
        kv := glitch_lib.all_attributes(parent)[_]
    } | {kv | 
        kv := glitch_lib.all_variables(parent)[_]
    }
    
    kv := all_key_values[_]
    name := lower(kv.name)
    name_matches := [keyword | keyword := sensitive_keywords[_]; contains(name, keyword)]
    count(name_matches) > 0
    
    kv.value.ir_type == "String"
    value := kv.value.value
    
    not regex.match("^[a-zA-Z0-9+/=]+$", value)
    not contains(value, "${")
    
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Hard-coded credential in attribute/variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_strings := {s | 
        walk(parent, [path, n])
        n.ir_type == "String"
        s := n
    }
    
    s := all_strings[_]
    value := s.value
    
    regex.match(private_key_pattern, value)
    
    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": "Hard-coded private key. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_strings := {s | 
        walk(parent, [path, n])
        n.ir_type == "String"
        s := n
    }
    
    s := all_strings[_]
    value := s.value
    
    api_key_pattern := api_key_patterns[_]
    regex.match(api_key_pattern, value)
    
    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": "Hard-coded API key. (CWE-798)"
    }
}