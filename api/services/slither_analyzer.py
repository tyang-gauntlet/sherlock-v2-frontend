import os
from typing import List, Dict, Any
from slither.slither import Slither


def analyze_with_slither(file_paths: List[str]) -> Dict[str, Any]:
    """
    Analyze Solidity files for potential vulnerabilities and code quality issues using Slither.

    Args:
        file_paths (List[str]): List of paths to Solidity files

    Returns:
        Dict[str, Any]: Analysis results including potential vulnerabilities and suggestions
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

    for file_path in file_paths:
        if not file_path.endswith('.sol'):
            continue

        try:
            # Initialize Slither
            slither = Slither(file_path)

            file_analysis = {
                'file_name': os.path.basename(file_path),
                'contracts': [],
                'total_functions': 0,
                'vulnerabilities': [],
                'suggestions': [],
                'compilation_successful': True
            }

            # Analyze each contract
            for contract in slither.contracts:
                contract_analysis = {
                    'name': contract.name,
                    'functions': [],
                    'state_variables': [],
                    'vulnerabilities': [],
                    'suggestions': []
                }

                # Analyze functions
                for function in contract.functions:
                    function_info = {
                        'name': function.name,
                        'visibility': str(function.visibility),
                        'modifiers': [m.name for m in function.modifiers],
                        'state_variables_written': [v.name for v in function.state_variables_written],
                        'line_number': function.source_mapping.lines[0] if function.source_mapping else None
                    }

                    # Check function-specific vulnerabilities
                    if function.payable:
                        contract_analysis['vulnerabilities'].append({
                            'type': 'PAYABLE_FUNCTION',
                            'severity': 'MEDIUM',
                            'description': f'Function "{function.name}" is payable at line {function.source_mapping.lines[0]}. Ensure proper access controls and reentrancy guards are in place.',
                            'line': function.source_mapping.lines[0] if function.source_mapping else None,
                            'contract': contract.name,
                            'function': function.name
                        })

                    for node in function.nodes:
                        for ir in node.irs:
                            ir_str = str(ir).lower()
                            line_number = node.source_mapping.lines[0] if node.source_mapping else None

                            if "selfdestruct" in ir_str:
                                contract_analysis['vulnerabilities'].append({
                                    'type': 'SELF_DESTRUCT',
                                    'severity': 'HIGH',
                                    'description': f'Self-destruct found in function "{function.name}" at line {line_number}. This is a high-risk operation that can permanently destroy the contract.',
                                    'line': line_number,
                                    'contract': contract.name,
                                    'function': function.name
                                })
                            if "delegatecall" in ir_str:
                                contract_analysis['vulnerabilities'].append({
                                    'type': 'DELEGATECALL',
                                    'severity': 'HIGH',
                                    'description': f'Delegatecall used in function "{function.name}" at line {line_number}. This is a dangerous operation that can lead to arbitrary code execution.',
                                    'line': line_number,
                                    'contract': contract.name,
                                    'function': function.name
                                })
                            if "block.timestamp" in ir_str:
                                contract_analysis['vulnerabilities'].append({
                                    'type': 'TIMESTAMP_DEPENDENCY',
                                    'severity': 'MEDIUM',
                                    'description': f'Block timestamp dependency in function "{function.name}" at line {line_number}. Miners can manipulate timestamps within a certain range.',
                                    'line': line_number,
                                    'contract': contract.name,
                                    'function': function.name
                                })

                    contract_analysis['functions'].append(function_info)
                    file_analysis['total_functions'] += 1

                # Analyze state variables
                for var in contract.state_variables:
                    var_info = {
                        'name': var.name,
                        'type': str(var.type),
                        'visibility': str(var.visibility),
                        'line_number': var.source_mapping.lines[0] if var.source_mapping else None
                    }
                    contract_analysis['state_variables'].append(var_info)

                # Run Slither detectors
                for detector in slither.detectors:
                    detector_results = detector.detect()
                    if detector_results:
                        for result in detector_results:
                            # Extract line numbers from source mapping if available
                            line_numbers = []
                            if 'source_mapping' in result:
                                line_numbers = result['source_mapping'].lines

                            vulnerability = {
                                'type': detector.__class__.__name__,
                                'severity': str(result.get('impact', 'MEDIUM')),
                                'description': f"{result.get('description', 'No description provided')} at line(s) {', '.join(map(str, line_numbers)) if line_numbers else 'unknown'}",
                                'lines': line_numbers,
                                'contract': result.get('contract', contract.name)
                            }
                            contract_analysis['vulnerabilities'].append(
                                vulnerability)

                # Add suggestions based on analysis
                if not any(f.get('modifiers', []) for f in contract_analysis['functions']):
                    contract_analysis['suggestions'].append({
                        'type': 'MISSING_MODIFIERS',
                        'severity': 'MEDIUM',
                        'description': f'Contract "{contract.name}" has functions without modifiers. Consider implementing access control modifiers for better security.',
                        'contract': contract.name,
                        'line': contract.source_mapping.lines[0] if contract.source_mapping else None
                    })

                public_vars = [
                    v for v in contract_analysis['state_variables'] if v['visibility'] == 'public']
                if len(public_vars) > 3:
                    var_lines = [v['line_number']
                                 for v in public_vars if v['line_number']]
                    contract_analysis['suggestions'].append({
                        'type': 'EXCESSIVE_PUBLIC_VARS',
                        'severity': 'LOW',
                        'description': f'Contract "{contract.name}" has {len(public_vars)} public state variables. Consider reducing visibility where possible. Public variables at lines: {", ".join(map(str, var_lines))}',
                        'contract': contract.name,
                        'lines': var_lines
                    })

                file_analysis['contracts'].append(contract_analysis)
                file_analysis['vulnerabilities'].extend(
                    contract_analysis['vulnerabilities'])
                file_analysis['suggestions'].extend(
                    contract_analysis['suggestions'])

            # Set risk level based on vulnerabilities
            if any(v['severity'] == 'HIGH' for v in file_analysis['vulnerabilities']):
                file_analysis['risk_level'] = 'HIGH'
                risk_levels.append('HIGH')
            elif any(v['severity'] == 'MEDIUM' for v in file_analysis['vulnerabilities']):
                file_analysis['risk_level'] = 'MEDIUM'
                risk_levels.append('MEDIUM')
            else:
                file_analysis['risk_level'] = 'LOW'
                risk_levels.append('LOW')

            results['files'].append(file_analysis)
            results['total_contracts'] += len(file_analysis['contracts'])
            results['total_functions'] += file_analysis['total_functions']
            results['vulnerabilities'].extend(file_analysis['vulnerabilities'])
            results['suggestions'].extend(file_analysis['suggestions'])

        except Exception as e:
            results['files'].append({
                'file_name': os.path.basename(file_path),
                'error': f'Slither Analysis failed: {str(e)}',
                'risk_level': 'UNKNOWN',
                'compilation_successful': False
            })
            risk_levels.append('UNKNOWN')

    # Calculate overall risk level
    if 'HIGH' in risk_levels:
        results['overall_risk_level'] = 'HIGH'
    elif 'MEDIUM' in risk_levels:
        results['overall_risk_level'] = 'MEDIUM'
    elif 'LOW' in risk_levels:
        results['overall_risk_level'] = 'LOW'
    else:
        results['overall_risk_level'] = 'UNKNOWN'

    # Sort vulnerabilities by severity
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    results['vulnerabilities'].sort(
        key=lambda x: severity_order.get(x['severity'].upper(), 3))

    return results
