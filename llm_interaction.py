"""
Interact with LLM via Pydantic framework (main file).
"""
import re
from pathlib import Path
from llm_interaction.conversation_templated import ask_model_prompt
from llm_interaction.conversation_templated import initialize_model, initialize_model_settings
from dotenv import load_dotenv
import os
from argparse import ArgumentParser
from validation.semantinc_checking import semantic_check
from validation.syntax_checking import opa_check

PROMPTS_DIR = Path(__file__).parent / "llm_interaction" / "prompts"


@ask_model_prompt(str(PROMPTS_DIR / "cwecondition.md"))
def get_cwe_condition(cwe: str, chat_history=None) -> str:
    """Get a CWE condition explanation from the LLM."""
    ...
    
@ask_model_prompt(str(PROMPTS_DIR / "regogeneration.md"))
def get_rego_generation(cwe: str, cwe_condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2:str,  chat_history=None) -> str:
    """Get a Rego generation from the LLM."""
    ...

@ask_model_prompt(str(PROMPTS_DIR / "syntaxerrorgeneration.md"))
def get_syntax_error_generation(error_message: str, chat_history=None) -> str:
    """Get a syntax error regeneration of the rule from the LLM."""
    ...
    
@ask_model_prompt(str(PROMPTS_DIR / "semanticerrorgeneration.md"))
def get_semantic_error_generation(ir_file: str, iac_language: str, line_number: int, chat_history=None) -> str:
    """Get a semantic error regeneration of the rule from the LLM."""
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
    
    with open(base_dir / f"prompt_data/cwes/CWE-{args.cwe}.json", "r") as f:
        cwe_text = f.read()
    
    cwe_condition = get_cwe_condition(cwe=cwe_text)
    print("CWE Condition Explanation:")
    print(cwe_condition)
    
    with open(base_dir / "prompt_data/glitch_lib.rego", "r") as f:
        rego_lib = f.read()
        
    with open(base_dir / "prompt_data/inter.txt", "r") as f:
        ir = f.read()
        
    with open(base_dir / "prompt_data/example_queries/sec_full_permission_filesystem.rego", "r") as f:
        example_rule_1 = f.read()
        
    with open(base_dir / "prompt_data/example_queries/sec_obsolete_command.rego", "r") as f:
        example_rule_2 = f.read()
    
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
    
    i = 1    
    while True:
        print(f"--- Validation Attempt {i} ---")
        i += 1
        
        # Replace the type name with the desired one
        rego_rule = replace_type_name(rego_rule, args.type_name)
        
        output_path = base_dir / f"generated_rego/CWE-{args.cwe}-{model_name}-generated.rego"
        
        with open(output_path, "w") as f:
            f.write(rego_rule)
        
        error = opa_check(str(base_dir / "prompt_data/glitch_lib.rego"), str(output_path))
        
        if error is not None:
            rego_rule = get_syntax_error_generation(error_message=error, chat_history=conversation_history)
            continue
        
        error = semantic_check(rego_rule, args.type_name, str(args.cwe))
        
        if error is not None:
            rego_rule = get_semantic_error_generation(ir_file=error[0], iac_language=error[1], line_number=error[2], chat_history=conversation_history)
            continue
        
        break
    
    
    
        
    