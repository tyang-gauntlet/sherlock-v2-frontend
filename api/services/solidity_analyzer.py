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

    for file_path in file_paths:
        logging.info(f"\n=== Starting analysis for {file_path} ===")
        if not file_path.endswith('.sol'):
            logging.warning(f"Skipping non-Solidity file: {file_path}")
            continue

        try:
            if not os.path.exists(file_path):
                logging.error(f"File does not exist: {file_path}")
                raise FileNotFoundError(f"File not found: {file_path}")

            logging.info(f"File exists and is readable: {file_path}")
            file_size = os.path.getsize(file_path)
            logging.info(f"File size: {file_size} bytes")

            # Print first few lines of the file
            logging.info("First few lines of the file:")
            with open(file_path, 'r') as f:
                first_lines = ''.join(f.readlines()[:5])
                logging.info(first_lines)

            # Get solc version from pragma
            solc_version = '0.8.28'  # Default version
            with open(file_path, 'r') as f:
                content = f.read()
                if 'pragma solidity' in content:
                    logging.info("Found solidity pragma in file")
                    # Extract solc version
                    import re
                    pragma_match = re.search(
                        r'pragma solidity\s*(\^?\d+\.\d+\.\d+)', content)
                    if pragma_match:
                        detected_version = pragma_match.group(
                            1).replace('^', '')  # Remove ^ if present
                        solc_version = detected_version
                        logging.info(
                            f"Detected Solidity version: {solc_version}")
                else:
                    logging.warning(
                        "No solidity pragma found in file, using default version")

            # Set up environment variables first
            venv_path = '/home/ubuntu/venv'
            env = os.environ.copy()
            env['PATH'] = f'{venv_path}/bin:/usr/bin:/usr/local/bin:{env.get("PATH", "")}'
            python_version = subprocess.check_output(
                ['python3', '-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'], text=True).strip()
            site_packages = f'{venv_path}/lib/python{python_version}/site-packages'
            env['PYTHONPATH'] = f'{site_packages}:{env.get("PYTHONPATH", "")}'
            env['SOLC_VERSION'] = solc_version
            # Add PYTHONUNBUFFERED to ensure we get all output
            env['PYTHONUNBUFFERED'] = '1'
            # Set SOLC path explicitly
            env['SOLC'] = '/usr/bin/solc'

            # Try to set solc version using solc-select
            try:
                solc_select_path = f'{venv_path}/bin/solc-select'
                if os.path.exists(solc_select_path):
                    # First install the required version
                    install_process = subprocess.run(
                        [solc_select_path, 'install', solc_version],
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if install_process.returncode == 0:
                        logging.info(
                            f"Successfully installed Solidity version {solc_version}")
                    else:
                        logging.error(
                            f"Failed to install Solidity version {solc_version}: {install_process.stderr}")
                        # Try to continue anyway as the version might already be installed

                    # Then use the version
                    use_process = subprocess.run(
                        [solc_select_path, 'use', solc_version],
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if use_process.returncode == 0:
                        logging.info(
                            f"Successfully set Solidity version to {solc_version}")
                    else:
                        logging.error(
                            f"Failed to set Solidity version {solc_version}: {use_process.stderr}")
                        raise Exception(
                            f"Failed to set Solidity version: {use_process.stderr}")
                else:
                    logging.error(
                        f"solc-select not found at {solc_select_path}")
                    raise Exception(
                        "solc-select not found, cannot set Solidity version")
            except subprocess.CalledProcessError as e:
                logging.error(f"Error during Solidity version setup: {e}")
                raise Exception(f"Failed to setup Solidity version: {e}")

            # Get absolute paths
            abs_file_path = os.path.abspath(file_path)

            # Verify solc version and location
            try:
                solc_check = subprocess.run(
                    ['solc', '--version'],
                    capture_output=True,
                    text=True,
                    env=env
                )
                if solc_check.returncode == 0:
                    logging.info(
                        f"Installed solc version: {solc_check.stdout}")
                else:
                    logging.error(
                        f"Failed to check solc version: {solc_check.stderr}")

                # Also check where solc is located
                which_solc = subprocess.run(
                    ['which', 'solc'],
                    capture_output=True,
                    text=True,
                    env=env
                )
                if which_solc.returncode == 0:
                    logging.info(f"solc location: {which_solc.stdout.strip()}")
                else:
                    logging.error("Could not find solc location")
            except Exception as e:
                logging.error(f"Error checking solc version: {e}")

            cmd = [f'{venv_path}/bin/python3', '-m', 'slither',
                   abs_file_path,
                   '--json', '-',
                   '--debug',
                   '--solc-disable-warnings']
            logging.info(f"Running command: {' '.join(cmd)}")

            # Log environment and file info for debugging
            logging.info(f"Environment PATH: {env['PATH']}")
            logging.info(f"Environment PYTHONPATH: {env['PYTHONPATH']}")
            logging.info(f"Environment SOLC_VERSION: {env['SOLC_VERSION']}")
            logging.info(f"Environment SOLC: {env['SOLC']}")
            logging.info(
                f"Working directory: {os.path.dirname(abs_file_path)}")
            logging.info(f"Using Solidity version: {solc_version}")
            logging.info(f"Python version: {python_version}")
            logging.info(f"File absolute path: {abs_file_path}")
            logging.info(f"File exists: {os.path.exists(abs_file_path)}")
            logging.info(
                f"File permissions: {oct(os.stat(abs_file_path).st_mode)[-3:]}")

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                    cwd=os.path.dirname(abs_file_path)
                )
                stdout, stderr = process.communicate()

                logging.info(f"Process return code: {process.returncode}")
                logging.info(f"Stdout length: {len(stdout) if stdout else 0}")
                if stdout:
                    logging.info(f"Stdout preview: {stdout[:1000]}...")
                logging.info(f"Stderr length: {len(stderr) if stderr else 0}")
                if stderr:
                    logging.error(f"Stderr output: {stderr}")

                # Try to parse JSON output regardless of return code
                if stdout and stdout.strip().startswith('{'):
                    try:
                        slither_output = json.loads(stdout)
                        logging.info("Successfully parsed Slither JSON output")

                        file_result = {
                            'file_name': os.path.basename(file_path),
                            'contracts': [],
                            'vulnerabilities': [],
                            'compilation_successful': True
                        }

                        # Extract vulnerabilities from detectors
                        if 'results' in slither_output and 'detectors' in slither_output['results']:
                            for detector in slither_output['results']['detectors']:
                                # Extract contract and function names from the first element if available
                                contract_name = ''
                                function_name = ''
                                if detector.get('elements'):
                                    element = detector['elements'][0]
                                    if element.get('type_specific_fields', {}).get('parent', {}).get('type') == 'contract':
                                        contract_name = element['type_specific_fields']['parent']['name']
                                    if element.get('type') == 'function':
                                        function_name = element['name']
                                    elif element.get('type_specific_fields', {}).get('parent', {}).get('type') == 'function':
                                        function_name = element['type_specific_fields']['parent']['name']

                                # Map Slither's severity levels
                                impact = detector.get('impact', 'UNKNOWN')
                                if impact == 'High':
                                    impact = 'HIGH'
                                elif impact == 'Medium':
                                    impact = 'MEDIUM'
                                elif impact == 'Low':
                                    impact = 'LOW'
                                elif impact == 'Informational':
                                    impact = 'INFO'

                                # Map confidence levels
                                confidence = detector.get(
                                    'confidence', 'UNKNOWN')
                                if confidence == 'High':
                                    confidence = 'HIGH'
                                elif confidence == 'Medium':
                                    confidence = 'MEDIUM'
                                elif confidence == 'Low':
                                    confidence = 'LOW'

                                vulnerability = {
                                    'type': detector.get('check', ''),
                                    'severity': impact,
                                    'confidence': confidence,
                                    'description': detector.get('description', ''),
                                    'contract': contract_name,
                                    'function': function_name
                                }
                                file_result['vulnerabilities'].append(
                                    vulnerability)
                                results['vulnerabilities'].append(
                                    vulnerability)

                        # Update statistics
                        results['files'].append(file_result)
                        results['total_contracts'] += 1
                        results['total_functions'] += len(
                            [v for v in file_result['vulnerabilities'] if v.get('function')])

                        logging.info(
                            f"Analysis completed successfully for {file_path}")
                        logging.info(
                            f"Found {len(file_result['vulnerabilities'])} vulnerabilities")
                        continue

                    except json.JSONDecodeError as e:
                        error_msg = f"Failed to parse Slither output: {e}"
                        logging.error(error_msg)
                        if stdout:
                            logging.error(
                                f"Invalid JSON output: {stdout[:1000]}...")
                        results['files'].append({
                            'file_name': os.path.basename(file_path),
                            'error': error_msg,
                            'compilation_successful': False
                        })
                        continue

                # If we get here, either there was no stdout or it wasn't valid JSON
                error_msg = stderr if stderr else "No valid output from Slither"
                if stdout and not stdout.strip().startswith('{'):
                    error_msg = f"Unexpected Slither output format: {stdout[:1000]}..."
                logging.error(f"Analysis failed: {error_msg}")
                results['files'].append({
                    'file_name': os.path.basename(file_path),
                    'error': f'Analysis failed: {error_msg}',
                    'compilation_successful': False
                })

            except Exception as e:
                error_msg = f"Failed to run Slither: {str(e)}"
                logging.error(error_msg)
                results['files'].append({
                    'file_name': os.path.basename(file_path),
                    'error': error_msg,
                    'compilation_successful': False
                })
                continue

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
