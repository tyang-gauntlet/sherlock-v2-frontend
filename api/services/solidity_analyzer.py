import os
import json
import subprocess
import logging
from typing import List, Dict, Any

# Set up logging
logging.basicConfig(
    filename='/var/log/sherlock-api.analysis.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def validate_solidity_file(file_path: str) -> tuple[bool, str]:
    """
    Validate a Solidity file before analysis.

    Args:
        file_path (str): Path to the Solidity file

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # Check if file is empty
        if not content.strip():
            return False, "File is empty"

        # Check for basic Solidity structure
        if 'contract' not in content and 'library' not in content and 'interface' not in content:
            return False, "File does not contain a valid Solidity contract, library, or interface"

        # Check for pragma
        if 'pragma solidity' not in content:
            return False, "Missing Solidity version pragma"

        return True, ""
    except Exception as e:
        return False, f"Error reading file: {str(e)}"


def analyze_solidity_files(file_paths: List[str]) -> Dict[str, Any]:
    """
    Analyze Solidity files for potential vulnerabilities using Slither CLI.

    Args:
        file_paths (List[str]): List of paths to Solidity files

    Returns:
        Dict[str, Any]: Analysis results including potential vulnerabilities and suggestions
    """
    logging.info(f"Starting analysis with file paths: {file_paths}")

    results = {
        'files': [],
        'total_contracts': 0,
        'total_functions': 0,
        'vulnerabilities': [],
        'overall_risk_level': 'LOW'
    }

    # Check if any files were provided
    if not file_paths:
        logging.error("No files provided for analysis")
        return results

    # Check if solc and slither are installed
    try:
        # Check solc installation
        solc_version_cmd = subprocess.run(
            ['solc', '--version'], capture_output=True, text=True)
        if solc_version_cmd.returncode != 0:
            logging.error("solc is not installed or not in PATH")
            results['error'] = "Solidity compiler (solc) is not properly configured"
            return results

        # Check slither installation
        slither_version_cmd = subprocess.run(
            ['slither', '--version'], capture_output=True, text=True)
        if slither_version_cmd.returncode != 0:
            logging.error("slither is not installed or not in PATH")
            results['error'] = "Slither analyzer is not properly configured"
            return results
    except Exception as e:
        logging.error(f"Error checking tool installation: {str(e)}")
        results['error'] = "Failed to verify analysis tools installation"
        return results

    for file_path in file_paths:
        logging.info(f"\n=== Starting analysis for {file_path} ===")
        if not file_path.endswith('.sol'):
            logging.warning(f"Skipping non-Solidity file: {file_path}")
            continue

        try:
            if not os.path.exists(file_path):
                logging.error(f"File does not exist: {file_path}")
                results['files'].append({
                    'file_name': os.path.basename(file_path),
                    'error': 'File not found',
                    'compilation_successful': False
                })
                continue

            # Validate the Solidity file
            is_valid, error_msg = validate_solidity_file(file_path)
            if not is_valid:
                logging.error(f"Invalid Solidity file: {error_msg}")
                results['files'].append({
                    'file_name': os.path.basename(file_path),
                    'error': f'Invalid Solidity file: {error_msg}',
                    'compilation_successful': False
                })
                continue

            # Get solc version from pragma
            solc_version = '0.8.28'  # Default version
            with open(file_path, 'r') as f:
                content = f.read()
                if 'pragma solidity' in content:
                    import re
                    pragma_match = re.search(
                        r'pragma solidity\s*(\^?\d+\.\d+\.\d+)', content)
                    if pragma_match:
                        detected_version = pragma_match.group(
                            1).replace('^', '')
                        solc_version = detected_version
                        logging.info(
                            f"Detected Solidity version: {solc_version}")
                else:
                    logging.warning(
                        "No solidity pragma found in file, using default version")

            # Set up environment
            env = os.environ.copy()
            env['SOLC_VERSION'] = solc_version
            env['PATH'] = f"/usr/local/bin:/usr/bin:/bin:{env.get('PATH', '')}"
            env['PYTHONPATH'] = f"/usr/local/lib/python3.12/site-packages:{env.get('PYTHONPATH', '')}"

            # Ensure the solc version is available
            try:
                # Try to install the required solc version if not already installed
                subprocess.run(
                    ['solc-select', 'install', solc_version],
                    capture_output=True,
                    text=True,
                    env=env
                )
                # Use the required version
                subprocess.run(
                    ['solc-select', 'use', solc_version],
                    capture_output=True,
                    text=True,
                    env=env
                )
            except Exception as e:
                logging.error(f"Failed to set up solc version: {str(e)}")
                # Continue with default version

            # Log environment setup for debugging
            logging.info(f"Environment PATH: {env['PATH']}")
            logging.info(f"Environment PYTHONPATH: {env['PYTHONPATH']}")
            logging.info(f"Using Solidity version: {solc_version}")

            # Run Slither analysis
            abs_file_path = os.path.abspath(file_path)
            cmd = ['slither', abs_file_path, '--json',
                   '-', '--solc-disable-warnings']

            try:
                # First check if the file can be compiled
                solc_check = subprocess.run(
                    ['solc', abs_file_path],
                    capture_output=True,
                    text=True,
                    env=env,
                    cwd=os.path.dirname(abs_file_path)
                )

                if solc_check.returncode != 0:
                    error_msg = f"Solidity compilation failed: {solc_check.stderr}"
                    logging.error(error_msg)
                    results['files'].append({
                        'file_name': os.path.basename(file_path),
                        'error': error_msg,
                        'compilation_successful': False
                    })
                    continue

                # Run Slither with detailed output
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=env,
                    cwd=os.path.dirname(abs_file_path),
                    timeout=300  # 5 minute timeout
                )

                # Log both stdout and stderr for debugging
                logging.info(f"Slither stdout: {process.stdout}")
                if process.stderr:
                    logging.error(f"Slither stderr: {process.stderr}")

                # Try to parse the JSON output first, regardless of return code
                try:
                    slither_output = json.loads(process.stdout)

                    # Check if analysis was successful based on the JSON output
                    if slither_output.get('success'):
                        file_result = {
                            'file_name': os.path.basename(file_path),
                            'contracts': [],
                            'vulnerabilities': [],
                            'compilation_successful': True
                        }

                        # Extract vulnerabilities from detectors
                        if 'results' in slither_output and 'detectors' in slither_output['results']:
                            for detector in slither_output['results']['detectors']:
                                # Extract contract and function names
                                elements = detector.get('elements', [])
                                contract_name = ''
                                function_name = ''

                                for element in elements:
                                    if element.get('type') == 'contract':
                                        contract_name = element.get('name', '')
                                    elif element.get('type') == 'function':
                                        function_name = element.get('name', '')
                                    elif element.get('type_specific_fields', {}).get('parent', {}).get('type') == 'contract':
                                        contract_name = element['type_specific_fields']['parent'].get(
                                            'name', '')
                                    elif element.get('type_specific_fields', {}).get('parent', {}).get('type') == 'function':
                                        function_name = element['type_specific_fields']['parent'].get(
                                            'name', '')

                                impact = detector.get(
                                    'impact', 'Unknown').capitalize()
                                confidence = detector.get(
                                    'confidence', 'Unknown').capitalize()

                                vulnerability = {
                                    'type': detector.get('check', ''),
                                    'severity': impact,
                                    'confidence': confidence,
                                    'description': detector.get('description', ''),
                                    'contract': contract_name,
                                    'function': function_name,
                                    'markdown': detector.get('markdown', ''),
                                    'first_markdown_element': detector.get('first_markdown_element', '')
                                }
                                file_result['vulnerabilities'].append(
                                    vulnerability)
                                results['vulnerabilities'].append(
                                    vulnerability)

                        results['files'].append(file_result)
                        results['total_contracts'] += 1
                        results['total_functions'] += len(
                            [v for v in file_result['vulnerabilities'] if v.get('function')])

                        logging.info(f"Successfully analyzed {file_path}")
                        logging.info(
                            f"Found {len(file_result['vulnerabilities'])} vulnerabilities")
                    else:
                        error_msg = slither_output.get(
                            'error', 'Unknown error during analysis')
                        logging.error(f"Slither analysis failed: {error_msg}")
                        results['files'].append({
                            'file_name': os.path.basename(file_path),
                            'error': f'Analysis failed: {error_msg}',
                            'compilation_successful': False
                        })

                except json.JSONDecodeError as e:
                    # Only handle process.returncode if JSON parsing fails
                    if process.returncode != 0:
                        error_msg = process.stderr if process.stderr else "Analysis failed without error message"
                        if "ModuleNotFoundError" in error_msg:
                            error_msg = "Slither dependencies not properly installed"
                        elif "SolcError" in error_msg:
                            error_msg = "Solidity compiler error: " + error_msg
                        elif "crytic_compile.platform.exceptions" in error_msg:
                            error_msg = "Contract compilation error: Please check your Solidity code"

                        logging.error(f"Slither analysis failed: {error_msg}")
                        results['files'].append({
                            'file_name': os.path.basename(file_path),
                            'error': f'Analysis failed: {error_msg}',
                            'compilation_successful': False
                        })
                    else:
                        error_msg = f"Failed to parse Slither output: {str(e)}"
                        logging.error(error_msg)
                        results['files'].append({
                            'file_name': os.path.basename(file_path),
                            'error': error_msg,
                            'compilation_successful': False
                        })

            except subprocess.TimeoutExpired:
                error_msg = "Analysis timed out after 5 minutes"
                logging.error(error_msg)
                results['files'].append({
                    'file_name': os.path.basename(file_path),
                    'error': error_msg,
                    'compilation_successful': False
                })
            except Exception as e:
                error_msg = f"Error running Slither: {str(e)}"
                logging.error(error_msg)
                results['files'].append({
                    'file_name': os.path.basename(file_path),
                    'error': error_msg,
                    'compilation_successful': False
                })

        except Exception as e:
            error_msg = f"Exception during analysis: {str(e)}"
            logging.error(error_msg)
            logging.exception("Full traceback:")
            results['files'].append({
                'file_name': os.path.basename(file_path),
                'error': error_msg,
                'compilation_successful': False
            })

    # Calculate overall risk level
    if any(v['severity'].upper() == 'HIGH' for v in results['vulnerabilities']):
        results['overall_risk_level'] = 'HIGH'
    elif any(v['severity'].upper() == 'MEDIUM' for v in results['vulnerabilities']):
        results['overall_risk_level'] = 'MEDIUM'
    elif any(v['severity'].upper() == 'LOW' for v in results['vulnerabilities']):
        results['overall_risk_level'] = 'LOW'

    return results
