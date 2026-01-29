import subprocess

def opa_check(path_to_lib:str, path: str) -> str | None:
    result = subprocess.run(
        ["opa", "check", "--v0-compatible", path_to_lib, path],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("OPA check failed ❌")
        print(result.stderr)
        return result.stderr

    print("OPA check passed ✅")
    return None