package glitch

import data.glitch_lib

suspicious_patterns = {
    "TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "TEMP", "WORKAROUND", "DEBUG", "XXX",
    "insecure", "hardcoded", "default password", "bypass", "public access", "no auth", "unencrypted",
    "NOTE", "cannot change", "break the cookbook", "issues", "tracker", "deprecated"
}

is_suspicious_comment(comment_str) {
    pattern := suspicious_patterns[_]
    regex.match(sprintf("(?i)\\b%s\\b", [pattern]), comment_str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check comments in UnitBlock's comments field (Ansible)
    comment := parent.comments[_]
    is_suspicious_comment(comment.content)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found - The comment contains keywords that indicate unresolved security risks, incomplete implementations, or intentional weaknesses. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check comments in code strings (Chef, Puppet, and other embedded comments)
    walk(parent, [path, node])
    node.code != ""
    code_with_comments := node.code
    lines := regex.split("\n", code_with_comments)
    line := lines[_]
    trimmed_line := regex.replace(line, "^[[:space:]]*", "")
    comment_start := regex.replace(trimmed_line, "^(#.*)", "$1")
    comment_start != trimmed_line
    is_suspicious_comment(comment_start)
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment found - The comment contains keywords that indicate unresolved security risks, incomplete implementations, or intentional weaknesses. (CWE-546)"
    }
}