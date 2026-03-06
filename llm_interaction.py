"""
Interact with LLM via Pydantic framework (main file).
"""
import re
import logging
from pathlib import Path
from llm_interaction.conversation_templated import (
    ask_model_prompt,
    initialize_model,
    initialize_examples_model,
    initialize_model_settings,
)
from llm_interaction.generation_logging import (
    build_run_paths,
    create_generation_log,
    list_generated_example_files,
    persist_generation_log,
    serialize_semantic_failures,
    append_iteration,
    finalize_generation_log,
)
from dotenv import load_dotenv
import os
from argparse import ArgumentParser
from validation.semantinc_checking import prepare_semantic_examples, semantic_check
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

def clean_rego_code(rego_code: str) -> str:
    """
    Remove markdown code fence markers from Rego code.
    
    Strips: ```rego, ```, ` from start and end of the code.
    
    Args:
        rego_code: The Rego code that may contain markdown markers
    
    Returns:
        Cleaned Rego code without markdown markers
    """
    code = rego_code.strip()
    
    # Remove opening fence: ```rego or ```
    code = re.sub(r'^```+\s*rego?\s*\n?', '', code)
    
    # Remove closing fence: ```
    code = re.sub(r'\n?```+\s*$', '', code)
    
    return code.strip()

if __name__ == "__main__":
    parser = ArgumentParser(description="LLM Interaction Client")
    parser.add_argument("model", help="Model to use (e.g., xiaomi/mimo-v2-flash)")
    parser.add_argument("--cwe", help="Choose CWE to use")
    parser.add_argument("--type-name", help="Desired type name for the Rego rule", required=True)
    parser.add_argument("--use-rag", action="store_true", help="Enable RAG for syntax error assistance")
    parser.add_argument("--use-llm-examples", action="store_true", help="Use LLM-generated examples for semantic checking instead of static manifest")
    parser.add_argument("--examples-model", help="Model to use for generating semantic-check examples (default: same as main model)")
    parser.add_argument(
        "--experiment-name",
        required=True,
        help="Required experiment label used in generated file and directory paths (e.g., false_positives)",
    )
    args = parser.parse_args()

    load_dotenv()

    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")

    initialize_model_settings()
    if not args.model:
        raise ValueError("Model argument is required")
    initialize_model(OPENROUTER_API_KEY, args.model)
    if getattr(args, "use_llm_examples", False):
        initialize_examples_model(OPENROUTER_API_KEY, getattr(args, "examples_model", None) or args.model)

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

    run_paths = build_run_paths(
        base_dir=base_dir,
        model=args.model,
        cwe=str(args.cwe),
        experiment_name=args.experiment_name,
    )
    model_directory = run_paths["model_directory"]
    run_directory = run_paths["run_directory"]
    run_directory.mkdir(parents=True, exist_ok=True)
    output_path = run_paths["output_path"]
    log_path = run_paths["log_path"]
    generated_examples_dir = run_paths["generated_examples_dir"]
    experiment_name = run_paths["experiment_name"]
    run_id = run_paths["run_id"]
    examples_model_used = getattr(args, "examples_model", None) or args.model

    generation_log = create_generation_log(
        run_id=run_id,
        run_directory=run_directory,
        cwe=str(args.cwe),
        type_name=args.type_name,
        model_used=args.model,
        use_rag=bool(args.use_rag),
        output_rego_path=output_path,
        cwe_condition=cwe_condition,
        use_llm_examples=bool(getattr(args, "use_llm_examples", False)),
        examples_model=examples_model_used,
        generated_examples_dir=generated_examples_dir,
        experiment_name=experiment_name,
    )
    persist_generation_log(log_path, generation_log)

    examples_folder, semantic_examples = prepare_semantic_examples(
        type_name=args.type_name,
        cwe_number=str(args.cwe),
        use_llm_examples=bool(getattr(args, "use_llm_examples", False)),
        cwe_text=cwe_text if getattr(args, "use_llm_examples", False) else None,
        api_key=OPENROUTER_API_KEY if getattr(args, "use_llm_examples", False) else None,
        examples_model=getattr(args, "examples_model", None),
        model_directory=model_directory,
        generated_examples_dir=generated_examples_dir,
    )
    if getattr(args, "use_llm_examples", False):
        generation_log["example_generation"]["files"] = list_generated_example_files(examples_folder)
        persist_generation_log(log_path, generation_log)
    
    MAX_VALIDATION_ATTEMPTS = 20
    validation_passed = False

    def append_iteration_and_persist(iteration_payload: dict) -> None:
        append_iteration(generation_log, iteration_payload, MAX_VALIDATION_ATTEMPTS)
        persist_generation_log(log_path, generation_log)

    for attempt in range(1, MAX_VALIDATION_ATTEMPTS + 1):
        print(f"--- Validation Attempt {attempt}/{MAX_VALIDATION_ATTEMPTS} ---")
        
        # Clean markdown code fences from LLM-generated code
        rego_rule = clean_rego_code(rego_rule)
        
        # Replace the type name with the desired one
        rego_rule = replace_type_name(rego_rule, args.type_name)

        iteration_log = {
            "attempt": attempt,
            "rego_code": rego_rule,
            "errors": [],
            "status": "in_progress",
        }
        
        with open(output_path, "w") as f:
            f.write(rego_rule)
        
        error = opa_check(
            str((base_dir / "prompt_data/rego_library/glitch_lib.rego").resolve()),
            str(output_path.resolve()),
        )
        
        if error is not None:
            iteration_log["errors"].append(
                {
                    "error_type": "syntactic",
                    "annotation": "OPA syntax/type check failure",
                    "message": error,
                }
            )
            iteration_log["status"] = "syntactic_error"
            append_iteration_and_persist(iteration_log)

            # If at max attempts, don't regenerate - just exit
            if attempt >= MAX_VALIDATION_ATTEMPTS:
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
        
        failures = semantic_check(
            rego_rule,
            args.type_name,
            str(args.cwe),
            examples_folder=examples_folder,
            examples=semantic_examples,
        )
        
        if failures:
            iteration_log["errors"] = serialize_semantic_failures(failures)
            iteration_log["status"] = "semantic_error"
            append_iteration_and_persist(iteration_log)

            # If at max attempts, don't regenerate - just exit
            if attempt >= MAX_VALIDATION_ATTEMPTS:
                break

            # Format failures for the prompt
            formatted_failures = [
                {
                    "iac_language": f[1],
                    "missing_lines": f[2],
                    "false_positives": f[3],
                    "ir_file": f[0]
                }
                for f in failures
            ]
            rego_rule = get_semantic_error_generation(failures=formatted_failures, chat_history=conversation_history)
            continue

        iteration_log["status"] = "passed"
        append_iteration_and_persist(iteration_log)
        validation_passed = True
        
        break

    finalize_generation_log(generation_log, passed=validation_passed, max_attempts=MAX_VALIDATION_ATTEMPTS)
    persist_generation_log(log_path, generation_log)
    print(f"Generation log saved to: {log_path}")
    
    # Check if we hit the validation limit
    if not validation_passed:
        print(f"\n⚠️ Reached maximum validation attempts ({MAX_VALIDATION_ATTEMPTS})")
        print(f"Final rule written to: {output_path}")
        print("Validation did not pass - manual review required")
        exit(1)
    
    
    
        
    