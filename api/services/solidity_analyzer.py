import os
import json
import subprocess
import logging
from typing import List, Dict, Any

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Set up logging
logging.basicConfig(
    filename='logs/sherlock-api.analysis.log',
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
        'overall_risk_level': 'LOW',
        'analysis_details': []  # Track analysis progress for each file
    }

    try:
        # Check if any files were provided
        if not file_paths:
            logging.error("No files provided for analysis")
            results['error'] = "No files provided for analysis"
            return results

        # Check if solc and slither are installed
        try:
            # Check solc installation
            logging.info("Checking solc installation...")
            solc_version_cmd = subprocess.run(
                ['solc', '--version'], capture_output=True, text=True)
            if solc_version_cmd.returncode != 0:
                error_msg = f"solc is not installed or not in PATH. Error: {solc_version_cmd.stderr}"
                logging.error(error_msg)
                results['error'] = error_msg
                return results
            logging.info(f"solc version: {solc_version_cmd.stdout.strip()}")

            # Check slither installation
            logging.info("Checking slither installation...")
            slither_version_cmd = subprocess.run(
                ['slither', '--version'], capture_output=True, text=True)
            if slither_version_cmd.returncode != 0:
                error_msg = f"slither is not installed or not in PATH. Error: {slither_version_cmd.stderr}"
                logging.error(error_msg)
                results['error'] = error_msg
                return results
            logging.info(
                f"slither version: {slither_version_cmd.stdout.strip()}")
        except Exception as e:
            error_msg = f"Error checking tool installation: {str(e)}"
            logging.error(error_msg)
            results['error'] = error_msg
            return results

        for file_path in file_paths:
            file_result = {'file': file_path, 'status': 'pending'}
            try:
                logging.info(f"\n=== Starting analysis for {file_path} ===")
                file_result['status'] = 'validating'

                # Validate file exists
                if not os.path.exists(file_path):
                    error_msg = f"File not found: {file_path}"
                    logging.error(error_msg)
                    file_result['status'] = 'error'
                    file_result['error'] = error_msg
                    results['analysis_details'].append(file_result)
                    continue

                if not file_path.endswith('.sol'):
                    error_msg = f"Skipping non-Solidity file: {file_path}"
                    logging.warning(error_msg)
                    file_result['status'] = 'skipped'
                    file_result['error'] = error_msg
                    results['analysis_details'].append(file_result)
                    continue

                # Validate Solidity file
                is_valid, validation_error = validate_solidity_file(file_path)
                if not is_valid:
                    error_msg = f"Invalid Solidity file {file_path}: {validation_error}"
                    logging.error(error_msg)
                    file_result['status'] = 'invalid'
                    file_result['error'] = error_msg
                    results['analysis_details'].append(file_result)
                    continue

                # Run Slither analysis
                file_result['status'] = 'analyzing'
                cmd = ['slither', file_path, '--json', '-']
                logging.info(f"Running Slither command: {' '.join(cmd)}")

                process = subprocess.run(cmd, capture_output=True, text=True)

                # Log the complete output for debugging
                logging.info("=== Slither Analysis Output ===")
                logging.info(f"Return code: {process.returncode}")
                logging.info(f"Stdout: {process.stdout}")
                logging.info(f"Stderr: {process.stderr}")
                logging.info("==============================")

                # Parse Slither output
                if process.stdout:
                    try:
                        slither_output = json.loads(process.stdout)
                        detectors = []

                        # Extract detectors from results
                        if 'results' in slither_output and 'detectors' in slither_output['results']:
                            for detector in slither_output['results']['detectors']:
                                detector_info = {
                                    'check': detector.get('check', ''),
                                    'impact': detector.get('impact', ''),
                                    'confidence': detector.get('confidence', ''),
                                    'description': detector.get('description', ''),
                                    'elements': detector.get('elements', [])
                                }
                                detectors.append(detector_info)
                                logging.info(
                                    f"Found vulnerability: {detector_info['check']} ({detector_info['impact']} impact)")

                            results['vulnerabilities'].extend(detectors)
                            file_result['status'] = 'success'
                            file_result['vulnerabilities_found'] = len(
                                detectors)
                            logging.info(
                                f"Successfully analyzed {file_path} - Found {len(detectors)} vulnerabilities")
                        else:
                            error_msg = f"No detectors found in Slither output for {file_path}"
                            logging.error(error_msg)
                            file_result['status'] = 'failed'
                            file_result['error'] = error_msg
                    except json.JSONDecodeError as e:
                        error_msg = f"Failed to parse Slither output for {file_path}: {str(e)}"
                        logging.error(error_msg)
                        file_result['status'] = 'parse_error'
                        file_result['error'] = error_msg
                else:
                    error_msg = f"No output from Slither for {file_path}. Error: {process.stderr}"
                    logging.error(error_msg)
                    file_result['status'] = 'failed'
                    file_result['error'] = error_msg

            except Exception as e:
                error_msg = f"Error processing file {file_path}: {str(e)}"
                logging.error(error_msg)
                file_result['status'] = 'error'
                file_result['error'] = error_msg

            results['analysis_details'].append(file_result)

        # Calculate overall statistics
        successful_analyses = [
            r for r in results['analysis_details'] if r['status'] == 'success']
        results['total_files_analyzed'] = len(file_paths)
        results['successful_analyses'] = len(successful_analyses)
        results['total_vulnerabilities'] = len(results['vulnerabilities'])

        # Determine overall risk level based on vulnerability impacts
        high_impact = any(
            v['impact'] == 'High' for v in results['vulnerabilities'])
        medium_impact = any(
            v['impact'] == 'Medium' for v in results['vulnerabilities'])
        results['overall_risk_level'] = 'HIGH' if high_impact else (
            'MEDIUM' if medium_impact else 'LOW')

        logging.info("=== Analysis Summary ===")
        logging.info(
            f"Total files analyzed: {results['total_files_analyzed']}")
        logging.info(f"Successful analyses: {results['successful_analyses']}")
        logging.info(
            f"Total vulnerabilities found: {results['total_vulnerabilities']}")
        logging.info(f"Overall risk level: {results['overall_risk_level']}")

        return results

    except Exception as e:
        error_msg = f"Unexpected error during analysis: {str(e)}"
        logging.error(error_msg)
        results['error'] = error_msg
        return results
