package glitch

import data.glitch_lib

suspicious_keywords := {"bug", "bugs", "bugfix", "defect", "error", "hack", "hacky", "workaround", "kludge", "temp", "temporary", "fixme", "todo", "later", "postpone", "xxx", "incomplete", "securityfixme", "hacksecurity", "bypass", "debug", "donotdeploy", "insecure", "broken", "wip", "deprecated", "break", "cannot change", "will break"}

Glitch_Analysis[result] {
    unit := glitch_lib._gather_parent_unit_blocks[_]
    unit.path != ""
    
    comment := unit.comments[_]
    lower_content := lower(comment.content)
    keyword := suspicious_keywords[_]
    contains(lower_content, keyword)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": unit.path,
        "description": "Suspicious comment detected in file - indicates unresolved issues or technical debt. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    unit := glitch_lib._gather_parent_unit_blocks[_]
    unit.path != ""
    
    comment := unit.comments[_]
    
    # Check for external issue tracker references (e.g., http://tracker.ceph.com/issues/18126)
    regex.match(`https?://.*issues?\/\d+`, comment.content)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": unit.path,
        "description": "Suspicious comment with external issue tracker reference detected - indicates unresolved issues. (CWE-546)"
    }
}