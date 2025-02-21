#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from services.embedding_processor import EmbeddingProcessor
import logging
from pprint import pformat

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def test_vulnerability_detection():
    """Test vulnerability detection using known patterns from Tally"""
    # Load environment variables
    load_dotenv()

    # Initialize embedding processor
    embedding_processor = EmbeddingProcessor(
        os.getenv('PINECONE_API_KEY'),
        "us-east-1-aws",
        'smartsmart'
    )

    # Test cases with known vulnerability patterns
    test_cases = [
        {
            "name": "Governance Timing Attack",
            "content": """
            contract TallyGovernor {
                function execute(
                    address[] memory targets,
                    uint256[] memory values,
                    bytes[] memory calldatas,
                    bytes32 descriptionHash
                ) external payable virtual returns (uint256) {
                    require(state(proposalId) == ProposalState.Succeeded, "Proposal not succeeded");
                    _execute(targets, values, calldatas, descriptionHash);
                    return proposalId;
                }

                function queue(
                    address[] memory targets,
                    uint256[] memory values,
                    bytes[] memory calldatas,
                    bytes32 descriptionHash
                ) external returns (uint256) {
                    require(state(proposalId) == ProposalState.Succeeded, "Proposal not succeeded");
                    uint256 eta = block.timestamp + delay;
                    _queueOperations(proposalId, targets, values, calldatas, eta);
                    return proposalId;
                }
            }
            """,
        },
        {
            "name": "Unsafe Delegate Call",
            "content": """
            contract ProxyContract {
                address public admin;
                address public implementation;

                function upgradeImplementation(address newImplementation) external {
                    require(msg.sender == admin, "Not authorized");
                    implementation = newImplementation;
                }

                fallback() external payable {
                    address impl = implementation;
                    assembly {
                        calldatacopy(0, 0, calldatasize())
                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                        returndatacopy(0, 0, returndatasize())
                        switch result
                        case 0 { revert(0, returndatasize()) }
                        default { return(0, returndatasize()) }
                    }
                }
            }
            """,
        },
        {
            "name": "Reentrancy in Vote Delegation",
            "content": """
            contract VotingToken {
                mapping(address => uint256) public balances;
                mapping(address => address) public delegates;

                function delegate(address to) external {
                    require(to != address(0), "Cannot delegate to zero address");
                    address currentDelegate = delegates[msg.sender];
                    delegates[msg.sender] = to;
                    _moveDelegateVotes(currentDelegate, to, balances[msg.sender]);
                }

                function _moveDelegateVotes(address from, address to, uint256 amount) internal {
                    if (from != address(0)) {
                        // External call before state update
                        IVotingPower(from).decreaseVotingPower(amount);
                    }
                    if (to != address(0)) {
                        IVotingPower(to).increaseVotingPower(amount);
                    }
                }
            }
            """,
        },
        {
            "name": "Timelock Bypass",
            "content": """
            contract TallyTimelock {
                uint256 public constant MINIMUM_DELAY = 2 days;
                uint256 public delay;
                mapping(bytes32 => bool) public queuedTransactions;

                function executeTransaction(
                    address target,
                    uint256 value,
                    string memory signature,
                    bytes memory data,
                    uint256 eta
                ) external payable returns (bytes memory) {
                    bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
                    require(queuedTransactions[txHash], "Transaction hasn't been queued.");
                    require(block.timestamp >= eta, "Transaction hasn't surpassed time lock.");
                    require(block.timestamp <= eta + GRACE_PERIOD, "Transaction is stale.");

                    queuedTransactions[txHash] = false;

                    bytes memory callData;
                    if (bytes(signature).length == 0) {
                        callData = data;
                    } else {
                        callData = abi.encodePacked(bytes4(keccak256(bytes(signature))), data);
                    }

                    (bool success, bytes memory returnData) = target.call{value: value}(callData);
                    require(success, "Transaction execution reverted.");

                    return returnData;
                }
            }
            """,
        },
        {
            "name": "Access Control Vulnerability",
            "content": """
            contract TallyVoting {
                address public owner;
                mapping(address => bool) public operators;
                mapping(address => uint256) public votingPower;

                modifier onlyOperator() {
                    require(operators[msg.sender], "Not an operator");
                    _;
                }

                function setVotingPower(address user, uint256 amount) external onlyOperator {
                    // Missing validation of operator privileges
                    votingPower[user] = amount;
                }

                function addOperator(address newOperator) external {
                    // Missing access control
                    operators[newOperator] = true;
                }
            }
            """,
        }
    ]

    logger.info("\nTesting Vulnerability Detection")
    logger.info("==============================")

    for test_case in test_cases:
        logger.info(f"\nTesting: {test_case['name']}")
        logger.info("=" * (8 + len(test_case['name'])))

        # Prepare test code with additional context
        test_code = {
            "content": test_case['content'],
            "repo_name": "test_repo",
            "file_path": "test.sol",
            "directory": "contracts"
        }

        # Analyze for vulnerabilities
        logger.info("Analyzing code for potential vulnerabilities...")
        vulnerabilities = embedding_processor.analyze_code_for_vulnerabilities(
            test_code)

        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                logger.info(f"\nPotential Vulnerability #{i}:")
                logger.info(
                    f"Location: Lines {vuln['code_location']['start_line']}-{vuln['code_location']['end_line']}")

                logger.info("\nSimilar Known Vulnerabilities:")
                for similar in vuln['similar_vulnerabilities']:
                    logger.info(f"\n- Title: {similar['title']}")
                    logger.info(f"  Severity: {similar['severity']}")
                    logger.info(f"  Category: {similar['category']}")
                    logger.info(f"  Repository: {similar['repo_name']}")
                    logger.info(
                        f"  Similarity Score: {similar['similarity_score']:.2f}")

                    if similar.get('description'):
                        logger.info(
                            f"\n  Description: {similar['description'][:300]}...")
                    if similar.get('mitigation'):
                        logger.info(
                            f"\n  Mitigation: {similar['mitigation'][:300]}...")
        else:
            logger.info("No similar vulnerabilities found")

    # Test with actual Tally code patterns
    logger.info("\nTesting with actual Tally code patterns")
    logger.info("=====================================")

    tally_test_cases = [
        {
            "name": "Tally Governance Implementation",
            "content": """
            contract TallyGovernor is Governor, GovernorSettings, GovernorTimelockControl {
                constructor(
                    string memory name_,
                    IVotes token_,
                    TimelockController timelock_,
                    uint256 votingDelay_,
                    uint256 votingPeriod_,
                    uint256 proposalThreshold_
                )
                    Governor(name_)
                    GovernorSettings(votingDelay_, votingPeriod_, proposalThreshold_)
                    GovernorTimelockControl(timelock_)
                {}

                function propose(
                    address[] memory targets,
                    uint256[] memory values,
                    bytes[] memory calldatas,
                    string memory description
                ) public override(Governor, IGovernor) returns (uint256) {
                    return super.propose(targets, values, calldatas, description);
                }

                function execute(
                    address[] memory targets,
                    uint256[] memory values,
                    bytes[] memory calldatas,
                    bytes32 descriptionHash
                ) public payable override(Governor, IGovernor) returns (uint256) {
                    return super.execute(targets, values, calldatas, descriptionHash);
                }
            }
            """,
        },
        {
            "name": "Tally Token Implementation",
            "content": """
            contract TallyToken is ERC20Votes {
                constructor(
                    string memory name_,
                    string memory symbol_,
                    uint256 initialSupply
                ) ERC20(name_, symbol_) ERC20Permit(name_) {
                    _mint(msg.sender, initialSupply);
                }

                function delegate(address delegatee) public override {
                    address oldDelegate = delegates(msg.sender);
                    _delegate(msg.sender, delegatee);
                    emit DelegateChanged(msg.sender, oldDelegate, delegatee);
                }

                function _afterTokenTransfer(
                    address from,
                    address to,
                    uint256 amount
                ) internal override {
                    super._afterTokenTransfer(from, to, amount);
                    _moveDelegates(delegates(from), delegates(to), amount);
                }
            }
            """,
        }
    ]

    for test_case in tally_test_cases:
        logger.info(f"\nTesting: {test_case['name']}")
        logger.info("=" * (8 + len(test_case['name'])))

        test_code = {
            "content": test_case['content'],
            "repo_name": "test_repo",
            "file_path": "test.sol",
            "directory": "contracts"
        }

        logger.info("Analyzing code for potential vulnerabilities...")
        vulnerabilities = embedding_processor.analyze_code_for_vulnerabilities(
            test_code)

        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                logger.info(f"\nPotential Vulnerability #{i}:")
                logger.info(
                    f"Location: Lines {vuln['code_location']['start_line']}-{vuln['code_location']['end_line']}")

                logger.info("\nSimilar Known Vulnerabilities:")
                for similar in vuln['similar_vulnerabilities']:
                    logger.info(f"\n- Title: {similar['title']}")
                    logger.info(f"  Severity: {similar['severity']}")
                    logger.info(f"  Category: {similar['category']}")
                    logger.info(f"  Repository: {similar['repo_name']}")
                    logger.info(
                        f"  Similarity Score: {similar['similarity_score']:.2f}")

                    if similar.get('description'):
                        logger.info(
                            f"\n  Description: {similar['description'][:300]}...")
                    if similar.get('mitigation'):
                        logger.info(
                            f"\n  Mitigation: {similar['mitigation'][:300]}...")
        else:
            logger.info("No similar vulnerabilities found")


if __name__ == "__main__":
    test_vulnerability_detection()
