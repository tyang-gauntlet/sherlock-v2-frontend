import os
from typing import List, Dict, Any
from solidity_parser import parser


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
            with open(file_path, 'r', encoding='utf-8') as file:
                source_code = file.read()

            # Parse Solidity code
            parsed_data = parser.parse(source_code)

            file_analysis = analyze_contract(parsed_data, source_code)
            file_analysis['file_name'] = os.path.basename(file_path)

            results['files'].append(file_analysis)
            results['total_contracts'] += len(
                file_analysis.get('contracts', []))
            results['total_functions'] += file_analysis.get(
                'total_functions', 0)
            results['vulnerabilities'].extend(
                file_analysis.get('vulnerabilities', []))
            results['suggestions'].extend(file_analysis.get('suggestions', []))

            risk_levels.append(file_analysis.get('risk_level', 'LOW'))

        except Exception as e:
            results['files'].append({
                'file_name': os.path.basename(file_path),
                'error': str(e),
                'risk_level': 'UNKNOWN'
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


def analyze_contract(parsed_data: Dict[str, Any], source_code: str) -> Dict[str, Any]:
    """
    Analyze a single Solidity contract.

    Args:
        parsed_data (Dict[str, Any]): Parsed Solidity AST
        source_code (str): Original source code

    Returns:
        Dict[str, Any]: Analysis results for the contract
    """
    results = {
        'contracts': [],
        'total_functions': 0,
        'vulnerabilities': [],
        'suggestions': [],
        'risk_level': 'LOW'
    }

    # Extract contracts
    contracts = [node for node in parsed_data['children']
                 if node['type'] == 'ContractDefinition']

    for contract in contracts:
        contract_analysis = {
            'name': contract['name'],
            'functions': [],
            'state_variables': [],
            'vulnerabilities': [],
            'suggestions': []
        }

        # Analyze functions
        functions = [node for node in contract['subNodes']
                     if node['type'] == 'FunctionDefinition']
        for func in functions:
            function_analysis = analyze_function(func)
            contract_analysis['functions'].append(function_analysis)
            results['total_functions'] += 1

        # Analyze state variables
        state_vars = [node for node in contract['subNodes']
                      if node['type'] == 'StateVariableDeclaration']
        for var in state_vars:
            var_analysis = analyze_state_variable(var)
            contract_analysis['state_variables'].append(var_analysis)

        # Check for common vulnerabilities
        vulnerabilities = check_vulnerabilities(contract, source_code)
        contract_analysis['vulnerabilities'].extend(vulnerabilities)
        results['vulnerabilities'].extend(vulnerabilities)

        # Add suggestions
        suggestions = generate_suggestions(contract_analysis)
        contract_analysis['suggestions'].extend(suggestions)
        results['suggestions'].extend(suggestions)

        results['contracts'].append(contract_analysis)

    # Update risk level based on vulnerabilities
    if any(v['severity'] == 'HIGH' for v in results['vulnerabilities']):
        results['risk_level'] = 'HIGH'
    elif any(v['severity'] == 'MEDIUM' for v in results['vulnerabilities']):
        results['risk_level'] = 'MEDIUM'

    return results


def analyze_function(func: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a single function"""
    return {
        'name': func.get('name', 'unnamed'),
        'visibility': func.get('visibility', 'public'),
        'modifiers': [mod['name'] for mod in func.get('modifiers', [])],
        'parameters': [{'name': param['name'], 'type': param['typeName']['name']}
                       for param in func.get('parameters', [])]
    }


def analyze_state_variable(var: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a state variable"""
    return {
        'name': var['variables'][0]['name'],
        'type': var['variables'][0]['typeName']['name'],
        'visibility': var.get('visibility', 'internal')
    }


def check_vulnerabilities(contract: Dict[str, Any], source_code: str) -> List[Dict[str, Any]]:
    """Check for common smart contract vulnerabilities"""
    vulnerabilities = []

    # Check for reentrancy
    if 'call.value' in source_code:
        vulnerabilities.append({
            'type': 'REENTRANCY',
            'severity': 'HIGH',
            'description': 'Potential reentrancy vulnerability detected'
        })

    # Check for unchecked external calls
    if '.call(' in source_code and 'require(' not in source_code:
        vulnerabilities.append({
            'type': 'UNCHECKED_EXTERNAL_CALL',
            'severity': 'MEDIUM',
            'description': 'Unchecked external call detected'
        })

    # Add more vulnerability checks as needed

    return vulnerabilities


def generate_suggestions(contract_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate code improvement suggestions"""
    suggestions = []

    # Check function visibility
    public_functions = [f for f in contract_analysis['functions']
                        if f['visibility'] == 'public']
    if len(public_functions) > 5:
        suggestions.append({
            'type': 'VISIBILITY',
            'severity': 'LOW',
            'description': 'Consider reducing the number of public functions'
        })

    # Check state variable visibility
    public_vars = [v for v in contract_analysis['state_variables']
                   if v['visibility'] == 'public']
    if len(public_vars) > 3:
        suggestions.append({
            'type': 'STATE_VISIBILITY',
            'severity': 'LOW',
            'description': 'Consider reducing the number of public state variables'
        })

    # Add more suggestions as needed

    return suggestions
