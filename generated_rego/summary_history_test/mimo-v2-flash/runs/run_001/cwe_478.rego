package glitch

import data.glitch_lib

chain_has_default(cs) = has_default {
    chain := build_chain(cs)
    has_default := count([c | c := chain[_]; c.is_default == true]) > 0
}

build_chain(node) = chain {
    node.else_statement == null
    chain := [node]
} else = chain {
    node.else_statement != null
    rest := build_chain(node.else_statement)
    chain := [node] + rest
}