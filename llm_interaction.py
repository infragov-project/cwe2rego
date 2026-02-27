"""
Interact with LLM via Pydantic framework (main file).
"""
import re
import logging
from pathlib import Path
from llm_interaction.conversation_templated import ask_model_prompt
from llm_interaction.conversation_templated import initialize_model, initialize_model_settings
from dotenv import load_dotenv
import os
from argparse import ArgumentParser
from validation.semantinc_checking import semantic_check
from validation.syntax_checking import opa_check
from rag.rag import build_rag_index, retrieve_from_index, format_chunks

# Suppress HTTP request logs (must come after imports that configure logging)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

@ask_model_prompt("prompts/cwecondition.md")
def get_cwe_condition(cwe: str, chat_history=None) -> str:
    """Get a CWE condition explanation from the LLM."""
    ...
    
@ask_model_prompt("prompts/regogeneration.md")
def get_rego_generation(cwe: str, cwe_condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2:str,  chat_history=None) -> str:
    """Get a Rego generation from the LLM."""
    ...

@ask_model_prompt("prompts/syntaxerrorgeneration_norag.md")
def get_syntax_error_generation_norag(error_message: str, chat_history=None) -> str:
    """Get a syntax error regeneration without RAG assistance."""
    ...

@ask_model_prompt("prompts/syntaxerrorgeneration.md")
def get_syntax_error_generation(error_message: str, rag_context: str, chat_history=None) -> str:
    """Get a syntax error regeneration with RAG assistance."""
    ...
    
@ask_model_prompt("prompts/semanticerrorgeneration.md")
def get_semantic_error_generation(failures: list, chat_history=None) -> str:
    """Get a semantic error regeneration of the rule from the LLM.
    
    Args:
        failures: List of dicts with keys 'ir_file', 'iac_language', 'missing_lines', 'file_name'
        chat_history: Conversation history
    """
    ...

def replace_type_name(rego_code: str, desired_type: str) -> str:
    """
    Replace the type field value in the rego rule with the desired type name.
    
    Args:
        rego_code: The generated Rego code
        desired_type: The desired type name to use
    
    Returns:
        Modified Rego code with replaced type name
    """
    # Pattern to match: "type": "anything_here"
    pattern = r'"type"\s*:\s*"[^"]*"'
    replacement = f'"type": "{desired_type}"'
    
    return re.sub(pattern, replacement, rego_code)

if __name__ == "__main__":
    parser = ArgumentParser(description="LLM Interaction Client")
    parser.add_argument("model", help="Model to use (e.g., xiaomi/mimo-v2-flash)")
    parser.add_argument("--cwe", help="Choose CWE to use")
    parser.add_argument("--type-name", help="Desired type name for the Rego rule", required=True)
    parser.add_argument("--use-rag", action="store_true", help="Enable RAG for syntax error assistance")
    args = parser.parse_args()
    
    load_dotenv()

    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")
    
    initialize_model_settings()
    if not args.model:
        raise ValueError("Model argument is required")
    initialize_model(OPENROUTER_API_KEY, args.model)

    base_dir = Path(__file__).parent
    
    # Build Rego RAG index if enabled
    rego_index = None
    if args.use_rag:
        print("Building Rego RAG index...")
        rego_index = build_rag_index(
            source_dir=base_dir / "rag/rego",
            api_key=OPENROUTER_API_KEY,
            name="rego_syntax"
        )
    
    with open(base_dir / f"prompt_data/cwes/CWE-{args.cwe}.json", "r") as f:
        cwe_text = f.read()
    
    with open(base_dir / "prompt_data/rego_library/glitch_lib.rego", "r") as f:
        rego_lib = f.read()
        
    with open(base_dir / "prompt_data/inter.txt", "r") as f:
        ir = f.read()
        
    with open(base_dir / "prompt_data/example_queries/sec_full_permission_filesystem.rego", "r") as f:
        example_rule_1 = f.read()
        
    with open(base_dir / "prompt_data/example_queries/sec_obsolete_command.rego", "r") as f:
        example_rule_2 = f.read()
    
    cwe_condition = get_cwe_condition(cwe=cwe_text)
    print("CWE Condition Explanation:")
    print(cwe_condition)
    
    conversation_history = []
    rego_rule = get_rego_generation(
            cwe=args.cwe,
            cwe_condition=cwe_condition,
            ir=ir,
            rego_lib=rego_lib,
            example_rule_1=example_rule_1,
            example_rule_2=example_rule_2,
            chat_history=conversation_history
        )

    model_name = args.model.split("/")[-1]
    
    MAX_VALIDATION_ATTEMPTS = 20
    i = 1    
    while i <= MAX_VALIDATION_ATTEMPTS:
        print(f"--- Validation Attempt {i}/{MAX_VALIDATION_ATTEMPTS} ---")
        i += 1
        
        # Replace the type name with the desired one
        rego_rule = replace_type_name(rego_rule, args.type_name)
        
        model_directory = base_dir / "generated_rego" / model_name
        model_directory.mkdir(parents=True, exist_ok=True)
        output_path = model_directory / f"cwe_{args.cwe}.rego"
        
        with open(output_path, "w") as f:
            f.write(rego_rule)
        
        error = opa_check(str(base_dir / "prompt_data/rego_library/glitch_lib.rego"), str(output_path))
        
        if error is not None:
            # If at max attempts, don't regenerate - just exit
            if i > MAX_VALIDATION_ATTEMPTS:
                break
            # Use appropriate syntax error generation based on RAG flag
            if args.use_rag and rego_index is not None:
                rag_chunks = retrieve_from_index(rego_index, error, top_k=3)
                rag_context = format_chunks(rag_chunks)
                rego_rule = get_syntax_error_generation(
                    error_message=error,
                    rag_context=rag_context,
                    chat_history=conversation_history
                )
            else:
                rego_rule = get_syntax_error_generation_norag(
                    error_message=error,
                    chat_history=conversation_history
                )
            continue
        
        failures = semantic_check(rego_rule, args.type_name, str(args.cwe))
        
        if failures:
            # If at max attempts, don't regenerate - just exit
            if i > MAX_VALIDATION_ATTEMPTS:
                break
            # Format failures for the prompt
            formatted_failures = [
                {
                    "iac_language": f[1],
                    "missing_lines": f[2],
                    "ir_file": f[0]
                }
                for f in failures
            ]
            rego_rule = get_semantic_error_generation(failures=formatted_failures, chat_history=conversation_history)
            continue
        
        break
    
    # Check if we hit the validation limit
    if i > MAX_VALIDATION_ATTEMPTS:
        print(f"\n⚠️ Reached maximum validation attempts ({MAX_VALIDATION_ATTEMPTS})")
        print(f"Final rule written to: {output_path}")
        print("Validation did not pass - manual review required")
        exit(1)
    
    
    
        
    