from slither.slither import Slither


def analyze_contract(file_path):
    try:
        # Initialize Slither
        slither = Slither(file_path)

        # Print basic information
        print(f"\nAnalyzing {file_path}:")
        print(f"Number of contracts: {len(slither.contracts)}")

        # Print contract information
        for contract in slither.contracts:
            print(f"\nContract: {contract.name}")
            print(f"Functions: {len(contract.functions)}")

            print("\nFunction Analysis:")
            for function in contract.functions:
                print(f"\n  Function: {function.name}")
                print(f"  Visibility: {function.visibility}")
                print(f"  Modifiers: {[m.name for m in function.modifiers]}")
                print(
                    f"  State Variables Written: {[v.name for v in function.state_variables_written]}")

                # Check for common vulnerabilities
                if function.payable:
                    print("  WARNING: Function is payable")

                # Check for dangerous calls
                for node in function.nodes:
                    for ir in node.irs:
                        if str(ir).lower().find("selfdestruct") >= 0:
                            print("  CRITICAL: Contains selfdestruct")
                        if str(ir).lower().find("delegatecall") >= 0:
                            print("  CRITICAL: Uses delegatecall")
                        if str(ir).lower().find("block.timestamp") >= 0:
                            print("  WARNING: Uses block.timestamp")

            print("\nState Variables:")
            for var in contract.state_variables:
                print(f"  - {var.name}: {var.type} ({var.visibility})")

            # Run detectors
            print("\nRunning vulnerability detectors...")
            for detector in slither.detectors:
                results = detector.detect()
                if results:
                    print(f"\nDetector: {detector.__class__.__name__}")
                    for result in results:
                        print(f"  - {result['description']}")

    except Exception as e:
        print(f"Error analyzing contract: {str(e)}")


if __name__ == "__main__":
    analyze_contract("VulnerableContract.sol")
