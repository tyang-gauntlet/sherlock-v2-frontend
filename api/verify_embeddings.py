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
    for match in results.matches:
        print(f"\nID: {match.id}")
        print(f"Score: {match.score}")
        if match.metadata:
            print("Metadata:")
            for key, value in match.metadata.items():
                print(f"  {key}: {value}")


if __name__ == "__main__":
    verify_database_state()
