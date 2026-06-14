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
    set_usage_callback,
)
from llm_interaction.history import (
    trim_validation_history,
    append_iteration_summary_to_history,
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
from validation.semantic_checking import prepare_semantic_examples, semantic_check
from validation.syntax_checking import opa_check
from validation.tools import GlitchTool, KICSTool
from rag.rag import build_rag_index, retrieve_from_index, format_chunks

# Suppress HTTP request logs (must come after imports that configure logging)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

@ask_model_prompt("prompts/cwecondition.md")
def get_cwe_condition(cwe: str, chat_history=None) -> str:
    """Get a CWE condition explanation from the LLM."""
    ...

@ask_model_prompt("prompts/descriptioncondition.md")
def get_description_condition(description: str, chat_history=None) -> str:
    """Elaborate a natural language weakness description into a precise IaC condition."""
    ...

@ask_model_prompt("prompts/regogeneration_description.md")
def get_rego_generation_description(condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2: str, chat_history=None) -> str:
    """Get a GLITCH Rego rule from a natural language description condition."""
    ...

@ask_model_prompt("prompts/regogeneration_kics_description.md")
def get_rego_generation_kics_description(condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2: str, chat_history=None) -> str:
    """Get a KICS Rego rule from a natural language description condition."""
    ...

@ask_model_prompt("prompts/regogeneration.md")
def get_rego_generation(cwe: str, cwe_condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2:str,  chat_history=None) -> str:
    """Get a Rego generation from the LLM."""
    ...


@ask_model_prompt("prompts/regogeneration_kics.md")
def get_rego_generation_kics(cwe: str, cwe_condition: str, ir: str, rego_lib: str, example_rule_1: str, example_rule_2: str, chat_history=None) -> str:
    """Get a KICS-style Rego generation (package Cx, CxPolicy[result]) from the LLM."""
    ...

@ask_model_prompt("prompts/syntaxerrorgeneration_norag.md")
def get_syntax_error_generation_norag(rego_rule: str, error_message: str, chat_history=None) -> str:
    """Get a syntax error regeneration without RAG assistance."""
    ...

@ask_model_prompt("prompts/syntaxerrorgeneration.md")
def get_syntax_error_generation(rego_rule: str, error_message: str, rag_context: str, chat_history=None) -> str:
    """Get a syntax error regeneration with RAG assistance."""
    ...

@ask_model_prompt("prompts/syntaxerrorgeneration_kics_norag.md")
def get_syntax_error_generation_kics_norag(rego_rule: str, error_message: str, chat_history=None) -> str:
    """Get a KICS-specific syntax error regeneration without RAG assistance."""
    ...

@ask_model_prompt("prompts/syntaxerrorgeneration_kics.md")
def get_syntax_error_generation_kics(rego_rule: str, error_message: str, rag_context: str, chat_history=None) -> str:
    """Get a KICS-specific syntax error regeneration with RAG assistance."""
    ...
    
@ask_model_prompt("prompts/semanticerrorgeneration.md")
def get_semantic_error_generation(
    rego_rule: str,
    failures: list,
    target_technologies: list[str],
    target_technologies_text: str,
    chat_history=None,
) -> str:
    """Get a semantic error regeneration of the rule from the LLM.

    Args:
        rego_rule: The current Rego rule to fix
        failures: List of dicts with keys 'ir_file', 'iac_language', 'missing_lines', 'false_positives'
        target_technologies: Technologies the rule should target
        target_technologies_text: Human-readable technologies list for the prompt
        chat_history: Conversation history
    """
    ...

@ask_model_prompt("prompts/semanticerrorgeneration_kics.md")
def get_semantic_error_generation_kics(
    rego_rule: str,
    failures: list,
    target_technologies: list[str],
    target_technologies_text: str,
    chat_history=None,
) -> str:
    """Get a KICS-specific semantic error regeneration of the rule from the LLM.

    Args:
        rego_rule: The current Rego rule to fix
        failures: List of dicts with keys 'ir_file', 'iac_language', 'missing_lines', 'false_positives', 'original_file_numbered'
        target_technologies: Technologies the rule should target
        target_technologies_text: Human-readable technologies list for the prompt
        chat_history: Conversation history
    """
    ...

@ask_model_prompt("prompts/summarize_syntactic_error.md")
def summarize_syntactic_error(rego_rule: str, error_message: str, chat_history=None) -> str:
    """Summarize a syntactic validation failure in natural language."""
    ...

@ask_model_prompt("prompts/summarize_semantic_error.md")
def summarize_semantic_error(rego_rule: str, failures: list, chat_history=None) -> str:
    """Summarize a semantic validation failure in natural language."""
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


def add_line_numbers(content: str) -> str:
    """Prefix each line with 1-based line numbers for annotation prompts."""
    lines = content.splitlines()
    if not lines:
        return ""
    return "\n".join(f"{index}: {line}" for index, line in enumerate(lines, start=1))


def _init_llm_usage_totals() -> dict:
    return {
        "calls": 0,
        "input_tokens_total": 0,
        "output_tokens_total": 0,
        "reasoning_tokens_total": 0,
        "cache_read_tokens_total": 0,
    }


def _accumulate_llm_usage(totals: dict, usage: dict) -> None:
    totals["calls"] += 1
    totals["input_tokens_total"] += int(usage.get("input_tokens", 0) or 0)
    totals["output_tokens_total"] += int(usage.get("output_tokens", 0) or 0)
    totals["reasoning_tokens_total"] += int(usage.get("reasoning_tokens", 0) or 0)
    totals["cache_read_tokens_total"] += int(usage.get("cache_read_tokens", 0) or 0)


def build_argument_parser() -> ArgumentParser:
    """Build and configure the CLI argument parser."""
    parser = ArgumentParser(description="LLM Interaction Client")
    parser.add_argument("model", help="Model to use (e.g., xiaomi/mimo-v2-flash)")
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--cwe", help="CWE number to use for rule generation")
    source_group.add_argument("--description", action="store_true", help="Use description mode: load weakness description from prompt_data/descriptions/<type_name>.txt")
    parser.add_argument("--type-name", help="Desired type name for the Rego rule", required=False)
    parser.add_argument("--condition-only", action="store_true", help="Only generate and save the condition, then exit")
    parser.add_argument(
        "--use-cwe-text",
        action="store_true",
        help="Use raw CWE text directly instead of generating a distilled CWE condition via LLM.",
    )
    parser.add_argument(
        "--use-description-text",
        action="store_true",
        help="Use the description as-is instead of elaborating it via LLM.",
    )
    parser.add_argument("--use-rag", action="store_true", help="Enable RAG for syntax error assistance")
    parser.add_argument("--use-llm-examples", action="store_true", help="Use LLM-generated examples for semantic checking instead of static manifest")
    parser.add_argument(
        "--skip-semantic-check",
        action="store_true",
        help="Skip semantic validation and semantic-regeneration; only enforce syntax/type validation.",
    )
    parser.add_argument("--examples-model", help="Model to use for generating semantic-check examples (default: same as main model)")
    parser.add_argument(
        "--validation-history-iterations",
        type=int,
        default=None,
        help=(
            "Number of most recent validation-fix iterations to retain in history. "
            "When omitted, full validation history is preserved. "
            "Pinned messages are controlled separately by --validation-history-pinned-messages. "
            "Set 0 to keep only the pinned messages. Set <0 to keep full validation history."
        ),
    )
    parser.add_argument(
        "--validation-history-pinned-messages",
        type=int,
        default=1,
        help=(
            "Number of earliest conversation-history messages to keep whenever validation-history "
            "truncation is enabled. Default: 1, which preserves the initial generation prompt."
        ),
    )
    parser.add_argument(
        "--semantic-examples-dir",
        help=(
            "Directory for static semantic examples when --use-llm-examples is disabled. "
            "Accepts either a base folder with <type_name>/ subfolders or a direct type folder. "
            "Default: validation/examples"
        ),
    )
    parser.add_argument(
        "--experiment-name",
        required=False,
        help="Experiment label used in generated file and directory paths (e.g., false_positives). Required unless --condition-only is set.",
    )
    parser.add_argument(
        "--analysis-tool",
        choices=["glitch", "kics"],
        default="glitch",
        help="Analysis tool for rule deployment and semantic check (default: glitch)",
    )
    parser.add_argument(
        "--technologies",
        nargs="*",
        default=None,
        metavar="TECH",
        help="Only run semantic check on these technologies (e.g. ansible chef). Omit to use all tool-supported types.",
    )
    return parser

if __name__ == "__main__":
    parser = build_argument_parser()
    args = parser.parse_args()

    load_dotenv()

    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")

    initialize_model_settings(args.model)
    if not args.model:
        raise ValueError("Model argument is required")
    if args.validation_history_pinned_messages < 0:
        parser.error("--validation-history-pinned-messages must be >= 0")
    initialize_model(OPENROUTER_API_KEY, args.model)
    if getattr(args, "use_llm_examples", False):
        initialize_examples_model(OPENROUTER_API_KEY, getattr(args, "examples_model", None) or args.model)

    llm_usage_totals = _init_llm_usage_totals()
    set_usage_callback(lambda usage: _accumulate_llm_usage(llm_usage_totals, usage))

    base_dir = Path(__file__).parent
    static_examples_dir = None
    if args.semantic_examples_dir:
        provided_examples_dir = Path(args.semantic_examples_dir).expanduser()
        static_examples_dir = (
            provided_examples_dir
            if provided_examples_dir.is_absolute()
            else (base_dir / provided_examples_dir)
        )

    if args.use_llm_examples and static_examples_dir is not None:
        print("Warning: --semantic-examples-dir is ignored because --use-llm-examples is enabled")

    if args.analysis_tool == "kics":
        KICSTool.install(base_dir)
        tool = KICSTool(base_dir)
    else:
        GlitchTool.install(base_dir)
        tool = GlitchTool(base_dir)

    target_technologies, unsupported_technologies = tool.resolve_technologies(
        args.technologies
    )
    if unsupported_technologies:
        print(
            f"Warning: ignoring unsupported technologies for {tool.name}: "
            f"{', '.join(unsupported_technologies)}"
        )
    target_technologies_text = tool.format_technologies(target_technologies)
    print(f"Semantic-check technologies: {target_technologies_text}")

    # Build Rego RAG index if enabled
    rego_index = None
    if args.use_rag:
        print("Building Rego RAG index...")
        rego_index = build_rag_index(
            source_dir=base_dir / "rag/rego",
            api_key=OPENROUTER_API_KEY,
            name="rego_syntax"
        )
    
    use_cwe = bool(args.cwe)
    if not use_cwe and not args.description:
        parser.error("Either --cwe or --description is required")

    # For description mode, type_name must be known before loading the description file
    if not use_cwe and not args.type_name and not args.condition_only:
        parser.error("--type-name is required when using --description")

    # Load input text (CWE JSON or type description file)
    if use_cwe:
        with open(base_dir / f"prompt_data/cwes/CWE-{args.cwe}.json", "r") as f:
            cwe_text = f.read()
    else:
        description_file = base_dir / "prompt_data" / "descriptions" / f"{args.type_name}.txt"
        if not description_file.exists():
            parser.error(f"Description file not found: {description_file}")
        with open(description_file, "r") as f:
            description_text = f.read()

    rego_lib = "\n\n".join(
        path.read_text() for path in tool.get_rego_lib_paths()
    )
    with open(tool.get_ir_description_path(), "r") as f:
        ir = f.read()
    example_paths = tool.get_example_rules_paths()
    with open(example_paths[0], "r") as f:
        example_rule_1 = f.read()
    with open(example_paths[1], "r") as f:
        example_rule_2 = f.read()

    # Generate or pass through the condition
    if use_cwe:
        condition = cwe_text if args.use_cwe_text else get_cwe_condition(cwe=cwe_text)
    else:
        condition = description_text if args.use_description_text else get_description_condition(description=description_text)

    if args.condition_only:
        from llm_interaction.generation_logging import model_to_directory_name
        if use_cwe:
            condition_dir = base_dir / "cwe_condition" / model_to_directory_name(args.model)
            condition_file = condition_dir / f"CWE-{args.cwe}.txt"
        else:
            if not args.type_name:
                parser.error("--type-name is required with --condition-only when using --description")
            condition_dir = base_dir / "rule_condition" / model_to_directory_name(args.model)
            condition_file = condition_dir / f"{args.type_name}.txt"
        condition_dir.mkdir(parents=True, exist_ok=True)
        condition_file.write_text(condition)
        print(f"Condition saved to {condition_file}")
        exit(0)

    if not args.type_name:
        parser.error("--type-name is required unless --condition-only is set")
    if not args.experiment_name:
        parser.error("--experiment-name is required unless --condition-only is set")

    # rule_id drives all output file naming
    rule_id = f"cwe_{args.cwe}" if use_cwe else args.type_name

    # Shared history starts at first rule generation; this pinned pair is preserved by trimming.
    conversation_history = []

    if args.analysis_tool == "kics":
        if use_cwe:
            rego_rule = get_rego_generation_kics(
                cwe=args.cwe,
                cwe_condition=condition,
                ir=ir,
                rego_lib=rego_lib,
                example_rule_1=example_rule_1,
                example_rule_2=example_rule_2,
                chat_history=conversation_history,
            )
        else:
            rego_rule = get_rego_generation_kics_description(
                condition=condition,
                ir=ir,
                rego_lib=rego_lib,
                example_rule_1=example_rule_1,
                example_rule_2=example_rule_2,
                chat_history=conversation_history,
            )
    else:
        if use_cwe:
            rego_rule = get_rego_generation(
                cwe=args.cwe,
                cwe_condition=condition,
                ir=ir,
                rego_lib=rego_lib,
                example_rule_1=example_rule_1,
                example_rule_2=example_rule_2,
                chat_history=conversation_history,
            )
        else:
            rego_rule = get_rego_generation_description(
                condition=condition,
                ir=ir,
                rego_lib=rego_lib,
                example_rule_1=example_rule_1,
                example_rule_2=example_rule_2,
                chat_history=conversation_history,
            )

    # Pop the initial response, keeping only the user prompt
    if len(conversation_history) >= 2:
        conversation_history.pop()

    run_paths = build_run_paths(
        base_dir=base_dir,
        model=args.model,
        rule_id=rule_id,
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
        rule_id=rule_id,
        type_name=args.type_name,
        model_used=args.model,
        use_rag=bool(args.use_rag),
        output_rego_path=output_path,
        condition=condition,
        use_llm_examples=bool(getattr(args, "use_llm_examples", False)),
        examples_model=examples_model_used,
        generated_examples_dir=generated_examples_dir,
        experiment_name=experiment_name,
        validation_history_iterations=args.validation_history_iterations,
        validation_history_pinned_messages=args.validation_history_pinned_messages,
        static_examples_dir=static_examples_dir,
    )
    generation_log["llm_usage"] = llm_usage_totals
    persist_generation_log(log_path, generation_log)

    examples_folder = None
    semantic_examples = []
    if args.skip_semantic_check:
        generation_log["semantic_examples"]["resolved_directory"] = None
        generation_log["semantic_examples"]["entries_count"] = 0
        generation_log["semantic_examples"]["skipped"] = True
    else:
        examples_folder, semantic_examples = prepare_semantic_examples(
            type_name=args.type_name,
            tool=tool,
            use_llm_examples=bool(getattr(args, "use_llm_examples", False)),
            condition_text=condition if getattr(args, "use_llm_examples", False) else None,
            cwe_number=str(args.cwe) if use_cwe else None,
            api_key=OPENROUTER_API_KEY if getattr(args, "use_llm_examples", False) else None,
            examples_model=getattr(args, "examples_model", None),
            model_directory=model_directory,
            generated_examples_dir=generated_examples_dir,
            target_technologies=target_technologies,
            static_examples_dir=static_examples_dir,
        )
        generation_log["semantic_examples"]["resolved_directory"] = str(Path(examples_folder).resolve())
        generation_log["semantic_examples"]["entries_count"] = len(semantic_examples)
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
        if args.validation_history_iterations is not None:
            trim_validation_history(
                conversation_history,
                args.validation_history_iterations,
                pinned_messages=args.validation_history_pinned_messages,
            )
        
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
        
        lib_path = tool.get_rego_lib_path().resolve()
        if tool.name == "kics":
            lib_path = lib_path.parent
        error = opa_check(
            str(lib_path),
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

            # If at max attempts, don't regenerate - just exit
            if attempt >= MAX_VALIDATION_ATTEMPTS:
                append_iteration_and_persist(iteration_log)
                break

            # Summarize this failure in natural language, log it, and add to history
            nl_summary = summarize_syntactic_error(rego_rule=rego_rule, error_message=error)
            iteration_log["nl_error_summary"] = nl_summary
            append_iteration_and_persist(iteration_log)
            append_iteration_summary_to_history(conversation_history, nl_summary)

            # Use appropriate syntax error generation based on RAG flag and analysis tool
            if args.use_rag and rego_index is not None:
                rag_chunks = retrieve_from_index(rego_index, error, top_k=3)
                rag_context = format_chunks(rag_chunks)
                if args.analysis_tool == "kics":
                    rego_rule = get_syntax_error_generation_kics(
                        rego_rule=rego_rule,
                        error_message=error,
                        rag_context=rag_context,
                        chat_history=conversation_history
                    )
                else:
                    rego_rule = get_syntax_error_generation(
                        rego_rule=rego_rule,
                        error_message=error,
                        rag_context=rag_context,
                        chat_history=conversation_history
                    )
            else:
                if args.analysis_tool == "kics":
                    rego_rule = get_syntax_error_generation_kics_norag(
                        rego_rule=rego_rule,
                        error_message=error,
                        chat_history=conversation_history
                    )
                else:
                    rego_rule = get_syntax_error_generation_norag(
                        rego_rule=rego_rule,
                        error_message=error,
                        chat_history=conversation_history
                    )

            # Pop the auto-appended user prompt and model response
            if len(conversation_history) >= 2:
                conversation_history.pop()  # Remove model response
                conversation_history.pop()  # Remove user prompt
            continue
        
        if args.skip_semantic_check:
            iteration_log["semantic_check_skipped"] = True
            iteration_log["status"] = "passed"
            append_iteration_and_persist(iteration_log)
            validation_passed = True
            break

        failures, passed, skipped_empty_ir = semantic_check(
            tool,
            rego_rule,
            args.type_name,
            examples_folder=examples_folder,
            examples=semantic_examples,
            technologies=target_technologies,
        )

        if skipped_empty_ir:
            iteration_log["skipped_empty_ir_files"] = skipped_empty_ir
            iteration_log["skipped_empty_ir_count"] = len(skipped_empty_ir)
        
        if failures:
            iteration_log["errors"] = serialize_semantic_failures(failures)
            iteration_log["status"] = "semantic_error"

            # If at max attempts, don't regenerate - just exit
            if attempt >= MAX_VALIDATION_ATTEMPTS:
                append_iteration_and_persist(iteration_log)
                break

            # Format failures for the summarizer and repair prompt
            formatted_failures = []
            for f in failures:
                # f is a tuple: (ir_file, iac_language, missing_lines, false_positives, file_name, ir_reduction_percentage)
                ir_file = f[0]
                iac_language = f[1]
                missing_lines = f[2]
                false_positives = f[3]
                file_name = f[4]
                ir_reduction_percentage = f[5]

                # Load original file content with line numbers
                original_file_path = Path(examples_folder) / file_name
                original_file_numbered = ""
                if original_file_path.exists():
                    original_content = original_file_path.read_text(encoding="utf-8")
                    original_file_numbered = add_line_numbers(original_content)

                formatted_failures.append({
                    "iac_language": iac_language,
                    "missing_lines": missing_lines,
                    "false_positives": false_positives,
                    "ir_file": ir_file,
                    "original_file_numbered": original_file_numbered,
                    "ir_reduction_percentage": ir_reduction_percentage,
                })

            # Summarize this failure in natural language, log it, and add to history
            nl_summary = summarize_semantic_error(rego_rule=rego_rule, failures=formatted_failures)
            iteration_log["nl_error_summary"] = nl_summary
            append_iteration_and_persist(iteration_log)
            append_iteration_summary_to_history(conversation_history, nl_summary)

            # Call appropriate semantic error generation function based on analysis tool
            if args.analysis_tool == "kics":
                rego_rule = get_semantic_error_generation_kics(
                    rego_rule=rego_rule,
                    failures=formatted_failures,
                    target_technologies=target_technologies,
                    target_technologies_text=target_technologies_text,
                    chat_history=conversation_history,
                )
            else:
                rego_rule = get_semantic_error_generation(
                    rego_rule=rego_rule,
                    failures=formatted_failures,
                    target_technologies=target_technologies,
                    target_technologies_text=target_technologies_text,
                    chat_history=conversation_history,
                )

            # Pop the auto-appended user prompt and model response
            if len(conversation_history) >= 2:
                conversation_history.pop()  # Remove model response
                conversation_history.pop()  # Remove user prompt
            continue

        iteration_log["status"] = "passed"
        append_iteration_and_persist(iteration_log)
        validation_passed = True
        
        break

    finalize_generation_log(generation_log, passed=validation_passed, max_attempts=MAX_VALIDATION_ATTEMPTS)
    persist_generation_log(log_path, generation_log)
    print(f"Generation log saved to: {log_path}")

    tool.remove_rule(args.type_name)

    if not validation_passed:
        print(f"\n⚠️ Reached maximum validation attempts ({MAX_VALIDATION_ATTEMPTS})")
        print(f"Final rule written to: {output_path}")
        print("Validation did not pass - manual review required")
        exit(1)
