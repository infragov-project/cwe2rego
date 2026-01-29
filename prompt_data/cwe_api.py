"""
CWE REST API Client

This module provides functions to query the Common Weakness Enumeration (CWE) 
REST API and retrieve information about specific weaknesses.

API Documentation: https://cwe-api.mitre.org/api/v1/
"""

import requests
from typing import List, Union, Optional
from argparse import ArgumentParser
from pathlib import Path
import os

CWE_API_BASE_URL = "https://cwe-api.mitre.org/api/v1"


def get_cwe_weaknesses(cwe_ids: Union[List[int], int]) -> List[dict]:
    """
    Retrieve information about one or more CWE weaknesses from the MITRE CWE API.

    Args:
        cwe_ids: A single CWE ID or a list of CWE IDs. Can be integers.

    Returns:
        A list of dictionaries containing CWE weakness information.

    Raises:
        requests.exceptions.RequestException: If the API request fails.
        ValueError: If no valid CWE IDs are provided.
    """
    # Normalize input to a list of strings
    if isinstance(cwe_ids, (int, str)):
        cwe_ids = [cwe_ids]
    
    if not cwe_ids:
        raise ValueError("At least one CWE ID must be provided")
    
    # Convert all IDs to strings and join with commas for the API
    id_str = ",".join(str(cwe_id) for cwe_id in cwe_ids)
    
    url = f"{CWE_API_BASE_URL}/cwe/weakness/{id_str}"
    
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    
    # The API may return a single weakness or a list; normalize to list
    if isinstance(data, dict):
        # Check if the response contains a 'Weaknesses' key (common API pattern)
        if "Weaknesses" in data:
            return data["Weaknesses"]
        # Otherwise wrap single result in a list
        return [data]
    elif isinstance(data, list):
        return data
    
    return []


def get_cwe_weakness(cwe_id: Union[int, str]) -> dict:
    """
    Retrieve information about a single CWE weakness.

    Args:
        cwe_id: The CWE ID to look up (e.g., 79 for XSS).

    Returns:
        A dictionary containing the CWE weakness information.

    Raises:
        requests.exceptions.RequestException: If the API request fails.
        IndexError: If the CWE ID is not found.
    """
    results = get_cwe_weaknesses(cwe_id)
    if not results:
        raise IndexError(f"CWE-{cwe_id} not found")
    return results[0]


def filter_cwe_relevant_fields(weakness_data: dict, relevant_fields: Optional[List[str]]=None) -> dict:
    """
    Filter CWE weakness data to include only relevant fields.

    Args:
        weakness_data: A dictionary containing CWE weakness information.

    Returns:
        A dictionary with only the relevant fields.
    """
    required_fields = [
        "ID",
        "Name",
        "Description",
    ]
    if not relevant_fields:
        relevant_fields = [
            "Extended_Description",
            "PotentialMitigations",
        ]
    relevant_fields = required_fields + relevant_fields

    for field in required_fields:
        if field not in weakness_data:
            raise KeyError(f"Missing required field `{field}` from CWE data")
    
    return {field: weakness_data.get(field) for field in relevant_fields}

def main():
    parser = ArgumentParser(description="CWE API Client")
    parser.add_argument("cwe_ids", nargs="+", help="CWE IDs to look up (e.g., 79 89 119)")
    parser.add_argument("--output-dir", help="Directory to save output", default="output")
    args = parser.parse_args()

    cwe_ids = [int(cwe_id) for cwe_id in args.cwe_ids]

    try:
        weaknesses = get_cwe_weaknesses(cwe_ids)
        filtered_weaknesses = weaknesses #[filter_cwe_relevant_fields(weakness) for weakness in weaknesses]

        output_dir = args.output_dir if args.output_dir else "output"
        output_dir = str(Path(output_dir).resolve())

        os.makedirs(output_dir, exist_ok=True)
        for weakness in filtered_weaknesses:
            output_path = f"{output_dir}/CWE-{weakness['ID']}.json" if args.output_dir else None
            if output_path:
                with open(output_path, "w") as f:
                    import json
                    json.dump(weakness, f, indent=4)
            else:
                raise ValueError("Output directory must be specified to save files.") # This should never happen

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()