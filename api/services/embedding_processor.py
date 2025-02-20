import os
from typing import Dict, List
import pinecone
from sentence_transformers import SentenceTransformer
import logging
from typing import Generator
import re

logger = logging.getLogger(__name__)


class EmbeddingProcessor:
    def __init__(self, pinecone_api_key: str, pinecone_environment: str, index_name: str):
        """
        Initialize the embedding processor with Pinecone connection
        """
        # Using CodeBERT-based model for better code understanding
        self.model = SentenceTransformer('microsoft/codebert-base')
        pinecone.init(api_key=pinecone_api_key,
                      environment=pinecone_environment)

        # Create index if it doesn't exist
        if index_name not in pinecone.list_indexes():
            pinecone.create_index(
                name=index_name,
                dimension=768,  # CodeBERT dimension
                metric="cosine"
            )

        self.index = pinecone.Index(index_name)

    def process_solidity_file(self, file_data: Dict) -> List[Dict]:
        """
        Process a Solidity file and create embeddings for:
        1. Contract definitions
        2. Function definitions
        3. Important code blocks
        """
        content = file_data["content"]
        chunks = self._chunk_solidity_code(content)

        embeddings = []
        for chunk in chunks:
            # Add Solidity-specific context to improve embedding quality
            contextualized_text = self._add_code_context(
                chunk["text"], chunk["type"])
            embedding = self.model.encode(contextualized_text)

            # Create metadata for the chunk
            metadata = {
                "type": "solidity_code",
                "repo_name": file_data["repo_name"],
                "file_path": file_data["file_path"],
                "chunk_type": chunk["type"],
                "start_line": chunk["start_line"],
                "end_line": chunk["end_line"],
                "content": chunk["text"]
            }

            embeddings.append({
                "id": f"{file_data['repo_name']}_{file_data['file_path']}_{chunk['start_line']}",
                "values": embedding.tolist(),
                "metadata": metadata
            })

        return embeddings

    def _add_code_context(self, code: str, chunk_type: str) -> str:
        """Add context to code chunks to improve embedding quality"""
        if chunk_type == "contract":
            return f"Solidity smart contract definition: {code}"
        elif chunk_type == "function":
            return f"Solidity function implementation: {code}"
        elif chunk_type == "modifier":
            return f"Solidity modifier definition: {code}"
        elif chunk_type == "event":
            return f"Solidity event definition: {code}"
        return f"Solidity code: {code}"

    def _chunk_solidity_code(self, content: str) -> List[Dict]:
        """
        Chunk Solidity code into meaningful parts using regex patterns
        """
        chunks = []
        lines = content.split('\n')

        # Pattern for contract definitions
        contract_pattern = r'^\s*contract\s+(\w+)'
        # Pattern for function definitions
        function_pattern = r'^\s*function\s+(\w+)'
        # Pattern for modifiers
        modifier_pattern = r'^\s*modifier\s+(\w+)'
        # Pattern for events
        event_pattern = r'^\s*event\s+(\w+)'

        current_chunk = []
        current_type = None
        start_line = 1

        for i, line in enumerate(lines, 1):
            if re.match(contract_pattern, line):
                if current_chunk:
                    chunks.append({
                        "text": "\n".join(current_chunk),
                        "type": current_type or "code_block",
                        "start_line": start_line,
                        "end_line": i - 1
                    })
                current_chunk = [line]
                current_type = "contract"
                start_line = i
            elif re.match(function_pattern, line):
                if current_chunk:
                    chunks.append({
                        "text": "\n".join(current_chunk),
                        "type": current_type or "code_block",
                        "start_line": start_line,
                        "end_line": i - 1
                    })
                current_chunk = [line]
                current_type = "function"
                start_line = i
            elif re.match(modifier_pattern, line):
                if current_chunk:
                    chunks.append({
                        "text": "\n".join(current_chunk),
                        "type": current_type or "code_block",
                        "start_line": start_line,
                        "end_line": i - 1
                    })
                current_chunk = [line]
                current_type = "modifier"
                start_line = i
            elif re.match(event_pattern, line):
                if current_chunk:
                    chunks.append({
                        "text": "\n".join(current_chunk),
                        "type": current_type or "code_block",
                        "start_line": start_line,
                        "end_line": i - 1
                    })
                current_chunk = [line]
                current_type = "event"
                start_line = i
            else:
                current_chunk.append(line)

        # Add the last chunk
        if current_chunk:
            chunks.append({
                "text": "\n".join(current_chunk),
                "type": current_type or "code_block",
                "start_line": start_line,
                "end_line": len(lines)
            })

        return chunks

    def process_vulnerability_report(self, report_data: Dict) -> List[Dict]:
        """
        Process a vulnerability report and create embeddings for:
        1. Vulnerability descriptions
        2. Impact descriptions
        3. Code references
        """
        content = report_data["content"]
        chunks = self._chunk_markdown_content(content)

        embeddings = []
        for chunk in chunks:
            # Add vulnerability-specific context
            contextualized_text = self._add_vulnerability_context(
                chunk["text"], chunk["type"])
            embedding = self.model.encode(contextualized_text)

            metadata = {
                "type": "vulnerability_report",
                "repo_name": report_data["repo_name"],
                "report_file": report_data["report_file"],
                "chunk_type": chunk["type"],
                "content": chunk["text"]
            }

            embeddings.append({
                "id": f"{report_data['repo_name']}_{report_data['report_file']}_{chunk['type']}",
                "values": embedding.tolist(),
                "metadata": metadata
            })

        return embeddings

    def _add_vulnerability_context(self, text: str, chunk_type: str) -> str:
        """Add context to vulnerability descriptions to improve embedding quality"""
        if chunk_type == "description":
            return f"Smart contract vulnerability description: {text}"
        elif chunk_type == "impact":
            return f"Vulnerability impact analysis: {text}"
        elif chunk_type == "code_reference":
            return f"Vulnerable code reference: {text}"
        return text

    def store_embeddings(self, embeddings: List[Dict], batch_size: int = 100):
        """Store embeddings in Pinecone in batches"""
        for i in range(0, len(embeddings), batch_size):
            batch = embeddings[i:i + batch_size]
            self.index.upsert(vectors=batch)

    def _chunk_markdown_content(self, content: str) -> List[Dict]:
        """
        Chunk markdown content into meaningful parts using regex patterns
        """
        # Split by headers
        chunks = []
        current_chunk = []
        current_type = None

        for line in content.split('\n'):
            if line.startswith('# '):
                if current_chunk:
                    chunks.append({
                        "text": "\n".join(current_chunk),
                        "type": current_type or "description"
                    })
                current_chunk = [line]
                current_type = self._determine_chunk_type(line.lower())
            else:
                current_chunk.append(line)

        # Add the last chunk
        if current_chunk:
            chunks.append({
                "text": "\n".join(current_chunk),
                "type": current_type or "description"
            })

        return chunks

    def _determine_chunk_type(self, header: str) -> str:
        """Determine the type of markdown chunk based on its header"""
        if any(word in header for word in ['impact', 'severity', 'risk']):
            return "impact"
        elif any(word in header for word in ['vulnerability', 'bug', 'issue']):
            return "description"
        elif any(word in header for word in ['code', 'poc', 'proof']):
            return "code_reference"
        return "description"
