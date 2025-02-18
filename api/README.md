# Solidity Code Analysis API

This API provides automated analysis of Solidity smart contracts, identifying potential vulnerabilities and suggesting improvements.

## Features

- File upload handling for Solidity (.sol) files
- Static code analysis
- Vulnerability detection
- Code quality suggestions
- Risk level assessment

## Setup

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```
5. Run the development server:
   ```bash
   python app.py
   ```

## Docker Deployment

1. Build the Docker image:
   ```bash
   docker build -t solidity-analyzer-api .
   ```
2. Run the container:
   ```bash
   docker run -p 5000:5000 -d solidity-analyzer-api
   ```

## EC2 Deployment

1. Launch an EC2 instance with Python 3.9
2. Install Docker on the instance
3. Clone the repository
4. Build and run the Docker container
5. Configure security groups to allow inbound traffic on port 5000

## API Endpoints

### Health Check

- `GET /health`
- Returns API health status

### Analyze Code

- `POST /analyze`
- Upload Solidity files for analysis
- Returns analysis results including:
  - Vulnerabilities
  - Suggestions
  - Risk level
  - Contract details

## Response Format

```json
{
  "files": [
    {
      "file_name": "Contract.sol",
      "contracts": [
        {
          "name": "MyContract",
          "functions": [...],
          "state_variables": [...],
          "vulnerabilities": [...],
          "suggestions": [...]
        }
      ],
      "risk_level": "LOW"
    }
  ],
  "overall_risk_level": "LOW",
  "total_contracts": 1,
  "total_functions": 5,
  "vulnerabilities": [...],
  "suggestions": [...]
}
```
