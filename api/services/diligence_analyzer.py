import os
import subprocess
from typing import List, Dict, Any
import json
from dotenv import load_dotenv

load_dotenv()


def analyze_with_diligence(file_paths: List[str]) -> Dict[str, Any]:
    """
    Analyze Solidity files using Diligence Fuzzing with Foundry integration.

    Args:
        file_paths (List[str]): List of paths to Solidity files

    Returns:
        Dict[str, Any]: Analysis results including potential vulnerabilities
    """
    results = {
        'files': [],
        'overall_risk_level': 'LOW',
        'total_contracts': 0,
        'total_functions': 0,
        'vulnerabilities': [],
        'suggestions': []
    }

    risk_levels = []

    # Create a temporary Foundry project structure
    project_dir = os.path.join(os.getcwd(), 'temp_foundry_project')
    os.makedirs(project_dir, exist_ok=True)
    os.makedirs(os.path.join(project_dir, 'src'), exist_ok=True)
    os.makedirs(os.path.join(project_dir, 'test'), exist_ok=True)

    try:
        # Copy Solidity files to src directory
        for file_path in file_paths:
            if not file_path.endswith('.sol'):
                continue

            file_name = os.path.basename(file_path)
            src_path = os.path.join(project_dir, 'src', file_name)
            with open(file_path, 'r') as src, open(src_path, 'w') as dst:
                content = src.read()
                dst.write(content)

            # Generate fuzzing test file
            test_name = f'Fuzz{os.path.splitext(file_name)[0]}Test.sol'
            test_path = os.path.join(project_dir, 'test', test_name)

            with open(test_path, 'w') as f:
                f.write(f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/{file_name}";

contract {os.path.splitext(file_name)[0]}Test is Test {{
    function setUp() public {{
    }}

    function testFuzz_Invariants(uint256 value) public {{
        // Basic fuzzing test
        vm.assume(value > 0);
        // Add more specific test logic here if needed
    }}
}}
''')

        # Initialize Foundry project
        subprocess.run(['forge', 'init', '--force'],
                       cwd=project_dir, check=True)

        # Run Diligence Fuzzing
        process = subprocess.run(
            ['fuzz', 'forge', 'test', '--dry-run'],
            cwd=project_dir,
            capture_output=True,
            text=True,
            env={**os.environ, 'FUZZ_API_KEY': os.getenv('FUZZ_API_KEY')}
        )

        if process.returncode != 0:
            raise Exception(f"Fuzzing failed: {process.stderr}")

        # Parse fuzzing results
        try:
            fuzzing_results = json.loads(process.stdout)
            for finding in fuzzing_results.get('findings', []):
                severity = finding.get('severity', 'LOW').upper()
                if severity == 'CRITICAL':
                    severity = 'HIGH'

                vulnerability = {
                    'type': finding.get('title', 'Unknown'),
                    'severity': severity,
                    'description': finding.get('description', ''),
                    'line': finding.get('line_number'),
                    'contract': finding.get('contract_name'),
                    'function': finding.get('function_name')
                }

                if severity in ['HIGH', 'MEDIUM', 'LOW']:
                    results['vulnerabilities'].append(vulnerability)
                else:
                    results['suggestions'].append({
                        'type': 'FUZZING_INSIGHT',
                        'severity': 'LOW',
                        'description': vulnerability['description'],
                        'line': vulnerability['line'],
                        'contract': vulnerability['contract']
                    })

            # Update risk levels
            if any(v['severity'] == 'HIGH' for v in results['vulnerabilities']):
                results['overall_risk_level'] = 'HIGH'
            elif any(v['severity'] == 'MEDIUM' for v in results['vulnerabilities']):
                results['overall_risk_level'] = 'MEDIUM'
            elif results['vulnerabilities']:
                results['overall_risk_level'] = 'LOW'

        except json.JSONDecodeError:
            raise Exception("Failed to parse fuzzing results")

    except Exception as e:
        results['files'].append({
            'error': f'Diligence Fuzzing Analysis failed: {str(e)}',
            'risk_level': 'UNKNOWN',
            'compilation_successful': False
        })

    finally:
        # Cleanup temporary project
        import shutil
        shutil.rmtree(project_dir, ignore_errors=True)

    # Sort vulnerabilities by severity
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    results['vulnerabilities'].sort(
        key=lambda x: severity_order.get(x['severity'].upper(), 3))

    return results
