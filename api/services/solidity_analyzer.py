import os
from typing import List, Dict, Any
from slither.slither import Slither


def analyze_solidity_files(file_paths: List[str]) -> Dict[str, Any]:
    """
    Analyze Solidity files for potential vulnerabilities and code quality issues.

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
                        'state_variables_written': [v.name for v in function.state_variables_written]
                    }

                    # Check function-specific vulnerabilities
                    if function.payable:
                        contract_analysis['vulnerabilities'].append({
                            'type': 'PAYABLE_FUNCTION',
                            'severity': 'MEDIUM',
                            'description': f'Function {function.name} is payable - ensure proper access controls'
                        })

                    for node in function.nodes:
                        for ir in node.irs:
                            ir_str = str(ir).lower()
                            if "selfdestruct" in ir_str:
                                contract_analysis['vulnerabilities'].append({
                                    'type': 'SELF_DESTRUCT',
                                    'severity': 'HIGH',
                                    'description': f'Function {function.name} contains selfdestruct - high risk'
                                })
                            if "delegatecall" in ir_str:
                                contract_analysis['vulnerabilities'].append({
                                    'type': 'DELEGATECALL',
                                    'severity': 'HIGH',
                                    'description': f'Function {function.name} uses delegatecall - potential security risk'
                                })
                            if "block.timestamp" in ir_str:
                                contract_analysis['vulnerabilities'].append({
                                    'type': 'TIMESTAMP_DEPENDENCY',
                                    'severity': 'MEDIUM',
                                    'description': f'Function {function.name} uses block.timestamp - potential manipulation'
                                })

                    contract_analysis['functions'].append(function_info)
                    file_analysis['total_functions'] += 1

                # Analyze state variables
                for var in contract.state_variables:
                    var_info = {
                        'name': var.name,
                        'type': str(var.type),
                        'visibility': str(var.visibility)
                    }
                    contract_analysis['state_variables'].append(var_info)

                # Run Slither detectors
                for detector in slither.detectors:
                    results = detector.detect()
                    if results:
                        for result in results:
                            vulnerability = {
                                'type': detector.__class__.__name__,
                                'severity': str(result.get('impact', 'MEDIUM')),
                                'description': result.get('description', 'No description provided')
                            }
                            contract_analysis['vulnerabilities'].append(
                                vulnerability)

                # Add suggestions based on analysis
                if not any(f.get('modifiers', []) for f in contract_analysis['functions']):
                    contract_analysis['suggestions'].append({
                        'type': 'MISSING_MODIFIERS',
                        'severity': 'MEDIUM',
                        'description': 'Consider using modifiers for access control'
                    })

                if len([v for v in contract_analysis['state_variables'] if v['visibility'] == 'public']) > 3:
                    contract_analysis['suggestions'].append({
                        'type': 'EXCESSIVE_PUBLIC_VARS',
                        'severity': 'LOW',
                        'description': 'Consider reducing the number of public state variables'
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
                'error': str(e),
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

    return results
