package glitch

import data.glitch_lib

excluded_domains := {"apache.org", "gnu.org", "mit.edu", "creativecommons.org", "creativecommons.net", "www.w3.org", "ietf.org", "stackoverflow.com", "serverfault.com", "superuser.com", "askubuntu.com", "example.com", "test"}

contains_excluded_url(comment) {
    some domain
    excluded_domains[domain]
    regex.match(sprintf(".*%s.*", [domain]), comment.content)
}

contains_non_excluded_url(comment) {
    regex.match("https?://[^\\s]+", comment.content)
    not contains_excluded_url(comment)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    
    # Define suspicious comment keywords pattern (case-insensitive)
    pattern := "(?i)\\b(TODO|FIXME|HACK|BUG|LATER|XXX|TEMP|WORKAROUND|DEBUG|CHECK|REMOVE|OPTIMIZE|REVIEW|INCOMPLETE|SECURITY|DEPRECATED|OBSOLETE|UNSAFE|INSECURE|VULNERABLE|WARNING|LIMITATION|CANNOT|BREAK)\\b"
    
    # Check if comment content matches suspicious keywords
    regex.match(pattern, comment.content)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found in IaC script indicating potential security concern or incomplete implementation (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    
    # Check for non-excluded URLs in comments
    contains_non_excluded_url(comment)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment with external URL found in IaC script indicating potential security concern or incomplete implementation (CWE-546)"
    }
}