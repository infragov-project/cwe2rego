"""
Interact with LLM via Pydantic framework (main file).
"""
from llm_interaction.conversation_templated import ask_model_prompt
from llm_interaction.conversation_templated import initialize_model, initialize_model_settings
from dotenv import load_dotenv
import os
from argparse import ArgumentParser


@ask_model_prompt("prompts/cwecondition.md")
def get_cwe_condition(cwe: str, chat_history=None) -> str:
    """Get a CWE condition explanation from the LLM."""
    ...
    
@ask_model_prompt("prompts/regogeneration.md")
def get_rego_generation(cwe: str, cwe_condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2:str,  chat_history=None) -> str:
    """Get a Rego generation from the LLM."""
    ...


if __name__ == "__main__":
    parser = ArgumentParser(description="LLM Interaction Client")
    parser.add_argument("model", help="Model to use (e.g., xiaomi/mimo-v2-flash)")
    parser.add_argument("--cwe", help="Choose CWE to use")
    args = parser.parse_args()
    
    load_dotenv()

    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")
    
    initialize_model_settings()
    if not args.model:
        raise ValueError("Model argument is required")
    initialize_model(OPENROUTER_API_KEY, args.model)

    with open(f"prompt_data/cwes/CWE-{args.cwe}.json", "r") as f:
        cwe_text = f.read()

    conversation_history = []
    
    cwe_condition = get_cwe_condition(cwe=cwe_text)
    print("CWE Condition Explanation:")
    print(cwe_condition)
    
    with open(f"prompt_data/glitch_lib.rego", "r") as f:
        rego_lib = f.read()
        
    with open(f"prompt_data/inter.txt", "r") as f:
        ir = f.read()
        
    with open(f"prompt_data/example_queries/sec_full_permission_filesystem.rego", "r") as f:
        example_rule_1 = f.read()
        
    with open(f"prompt_data/example_queries/sec_obsolete_command.rego", "r") as f:
        example_rule_2 = f.read()
    
    rego_rule = get_rego_generation(
        cwe=args.cwe,
        cwe_condition=cwe_condition,
        ir=ir,
        rego_lib=rego_lib,
        example_rule_1=example_rule_1,
        example_rule_2=example_rule_2
    )
    
    print("Generated Rego Rule:")
    print(rego_rule)
    
    with open(f"generated_rego/CWE-{args.cwe}-generated.rego", "w") as f:
        f.write(rego_rule)
    
    #print(get_cwe_condition(cwe="CWE-89", chat_history=conversation_history))
    