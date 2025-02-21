from services.embedding_processor import EmbeddingProcessor
import os
from dotenv import load_dotenv
import json
from pinecone import Pinecone

# Load environment variables
load_dotenv()


def verify_database_state():
    """Verify the state of the vector database"""
    print("\nVerifying Vector Database State:")
    print("================================")

    # Initialize Pinecone
    pc = Pinecone(api_key=os.getenv('PINECONE_API_KEY'))

    # List all indexes
    print("\nAvailable Indexes:")
    indexes = pc.list_indexes()
    for index in indexes.indexes:
        print(
            f"- {index.name} ({index.dimension} dimensions, {index.metric} metric)")
        print(f"  Status: {index.status.state}")
        print(f"  Host: {index.host}")

    # Get stats for our index
    index = pc.Index("smartsmart")
    stats = index.describe_index_stats()
    print("\nIndex Statistics:")
    print(f"Total vector count: {stats.total_vector_count}")

    if hasattr(stats, 'dimension_stats') and stats.dimension_stats:
        print("\nDimension distribution:")
        for dim, count in stats.dimension_stats.items():
            print(f"- {dim}: {count} vectors")

    if hasattr(stats, 'namespaces') and stats.namespaces:
        print("\nNamespace statistics:")
        for ns, count in stats.namespaces.items():
            print(f"- {ns}: {count} vectors")

    # Query for all vulnerability entries
    results = index.query(
        vector=[0.0] * 767 + [1.0],  # Dummy vector
        top_k=5,
        include_metadata=True,
        filter={"type": "vulnerability_code"}
    )

    print("\nSample Vulnerability Entries:")
    if not results.matches:
        print("No vulnerability entries found in the database")
    else:
        for match in results.matches:
            print(f"\n- Repository: {match.metadata.get('repo_name')}")
            print(f"  File: {match.metadata.get('file_path')}")
            print(f"  Type: {match.metadata.get('type')}")
            if match.metadata.get('title'):
                print(f"  Title: {match.metadata.get('title')}")
            if match.metadata.get('severity'):
                print(f"  Severity: {match.metadata.get('severity')}")


def test_vector_search():
    # Initialize embedding processor
    embedding_processor = EmbeddingProcessor(
        os.getenv('PINECONE_API_KEY'),
        "us-east-1-aws",
        'smartsmart'
    )

    # Test code with multiple potential vulnerabilities
    test_codes = [
        {
            "name": "Reentrancy vulnerability",
            "content": """
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount);
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] -= amount;
            }
            """,
        },
        {
            "name": "Integer overflow",
            "content": """
            function transfer(address to, uint256 amount) public {
                balances[to] += amount;
                balances[msg.sender] -= amount;
            }
            """,
        },
        {
            "name": "Unprotected function",
            "content": """
            function setOwner(address newOwner) public {
                owner = newOwner;
            }
            """,
        }
    ]

    for test_case in test_codes:
        print(f"\nTesting: {test_case['name']}")
        print("=" * (9 + len(test_case['name'])))

        test_code = {
            "content": test_case['content'],
            "repo_name": "test_repo",
            "file_path": "test.sol",
            "directory": "contracts"
        }

        # Analyze the test code
        print("Analyzing code for potential vulnerabilities...")
        vulnerabilities = embedding_processor.analyze_code_for_vulnerabilities(
            test_code)

        # Print results
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\nPotential Vulnerability #{i}:")
                print(
                    f"Code Location: Lines {vuln['code_location']['start_line']}-{vuln['code_location']['end_line']}")
                print("\nSimilar Known Vulnerabilities:")
                for similar in vuln['similar_vulnerabilities']:
                    print(f"\n- Title: {similar['title']}")
                    print(f"  Severity: {similar['severity']}")
                    print(f"  Category: {similar['category']}")
                    print(f"  Repository: {similar['repo_name']}")
                    print(
                        f"  Similarity Score: {similar['similarity_score']:.2f}")
                    if similar.get('description'):
                        print(
                            f"\n  Description: {similar['description'][:200]}...")
                    if similar.get('mitigation'):
                        print(
                            f"\n  Mitigation: {similar['mitigation'][:200]}...")
        else:
            print("No similar vulnerabilities found")


if __name__ == "__main__":
    # First verify the database state
    verify_database_state()

    # Then run the vector search tests
    print("\nRunning Vector Search Tests:")
    print("===========================")
    test_vector_search()
