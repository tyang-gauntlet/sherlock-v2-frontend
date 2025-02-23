import React, { useCallback, useState } from "react"
import { Box } from "../../../components/Box"
import { Button } from "../../../components/Button"
import { Column, Row } from "../../../components/Layout"
import { Text } from "../../../components/Text"
import { Title } from "../../../components/Title"
import { FaCloudUploadAlt, FaSpinner, FaExclamationTriangle, FaCheckCircle, FaInfoCircle } from "react-icons/fa"
import { getAPIURL } from "../../../utils/api"

import styles from "./CodeUploader.module.scss"

type AnalysisResult = {
  analysis_details: Array<{
    file: string
    status: string
    vulnerabilities_found: number
  }>
  files: string[]
  overall_risk_level: string
  successful_analyses: number
  total_contracts: number
  total_files_analyzed: number
  total_functions: number
  total_vulnerabilities: number
  vulnerabilities: Array<{
    check: string
    confidence: string
    description: string
    elements: Array<{
      name: string
      source_mapping: {
        filename_relative: string
        lines: number[]
        start: number
        length: number
      }
      type: string
    }>
    impact: string
  }>
  vulnerabilitiesByFile?: Record<
    string,
    Record<
      string,
      Array<{
        check: string
        confidence: string
        description: string
        elements: Array<{
          name: string
          source_mapping: {
            filename_relative: string
            lines: number[]
            start: number
            length: number
          }
          type: string
        }>
        impact: string
      }>
    >
  >
  ragAnalysis?: {
    files: Array<{
      file_name: string
      analysis_summary: string
      analyzed_documents: Array<{
        document_id: string
        metadata: {
          repo_name: string
          report_file: string
          file_path: string
          commit_hash: string
          timestamp: string
          type: string
          category: string
          severity: string
          start_line: number
          end_line: number
        }
        content: {
          code_snippet: string
          context: string
          description: string
        }
        similarity: {
          score: number
          vector_id: string
          embedding_model: string
          embedding_dimension: number
        }
        evaluation: {
          relevance_score: number
          explanation: string
          affected_regions: string[]
          risk_level: string
          confidence: number
        }
      }>
      statistics: {
        similarity_stats: any
        relevance_stats: any
        confidence_stats: any
        total_documents_retrieved: number
        total_documents_analyzed: number
        risk_level_distribution: {
          HIGH: number
          MEDIUM: number
          LOW: number
          NONE: number
        }
        category_distribution: Record<
          string,
          {
            count: number
            avg_relevance: number
            avg_similarity: number
          }
        >
      }
    }>
    model_info: {
      embedding_model: string
      llm_model: string
      embedding_dimension: number
      timestamp: string
    }
  }
}

type Finding = {
  category: string
  severity: string
  context: string
  similarity_score: number
  relevance_score: number
  affected_code?: string[]
  source: {
    repo_name: string
    file_path: string
    code_snippet: string
    start_line?: number
    end_line?: number
  }
}

type VulnerabilityGroup = {
  location: string
  scope: string
  codeContext: string
  findings: Finding[]
  aggregatedRisk: string
  recommendations: string[]
}

export const ContractAnalyzer: React.FC = () => {
  const [isDragging, setIsDragging] = useState(false)
  const [isUploading, setIsUploading] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fileVersions, setFileVersions] = useState<Record<string, string>>({})

  const sortBySeverity = useCallback((a: { severity: string }, b: { severity: string }) => {
    const severityOrder: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 }
    const aSeverity = a?.severity?.toUpperCase() ?? "UNKNOWN"
    const bSeverity = b?.severity?.toUpperCase() ?? "UNKNOWN"
    return (severityOrder[aSeverity] ?? 3) - (severityOrder[bSeverity] ?? 3)
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)

    const droppedFiles = Array.from(e.dataTransfer.files).filter(
      (file) => file.name.endsWith(".sol") || file.type === "application/json"
    )
    setFiles(droppedFiles)
    setAnalysisResult(null)
    setError(null)
    setFileVersions({}) // Reset versions when new files are dropped

    // Extract versions from dropped files
    droppedFiles.forEach(async (file) => {
      const version = await extractSolidityVersion(file)
      if (version) {
        setFileVersions((prev) => ({
          ...prev,
          [file.name]: version,
        }))
      }
    })
  }, [])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files).filter(
        (file) => file.name.endsWith(".sol") || file.type === "application/json"
      )
      setFiles(selectedFiles)
      setAnalysisResult(null)
      setError(null)
      setFileVersions({}) // Reset versions when new files are selected

      // Extract versions from new files
      selectedFiles.forEach(async (file) => {
        const version = await extractSolidityVersion(file)
        if (version) {
          setFileVersions((prev) => ({
            ...prev,
            [file.name]: version,
          }))
        }
      })
    }
  }, [])

  const extractSolidityVersion = async (file: File): Promise<string | null> => {
    const content = await file.text()
    const versionRegex = /pragma solidity\s+(\^?\d+\.\d+\.\d+|>=?\d+\.\d+\.\d+|<=?\d+\.\d+\.\d+)/
    const match = content.match(versionRegex)
    return match ? match[1] : null
  }

  const handleUpload = useCallback(async () => {
    if (files.length === 0) return

    setIsUploading(true)
    setError(null)
    const formData = new FormData()

    try {
      const versions = await Promise.all(files.map(extractSolidityVersion))
      const validVersions = versions.filter((v): v is string => v !== null)

      if (validVersions.length === 0) {
        throw new Error(
          "No valid Solidity version found in any of the files. Please ensure your contracts include a pragma solidity statement."
        )
      }

      // Add files and version information to formData
      files.forEach((file) => {
        formData.append("files", file)
      })
      formData.append("solidity_versions", JSON.stringify(validVersions))

      const apiUrl = await getAPIURL()

      // Run Slither analysis
      const analysisResponse = await fetch(`${apiUrl}/analyze`, {
        method: "POST",
        body: formData,
        credentials: "include",
      })

      if (!analysisResponse.ok) {
        const errorBody = await analysisResponse.text()
        let parsedError
        try {
          parsedError = JSON.parse(errorBody)
        } catch {
          parsedError = { error: errorBody }
        }

        // Handle specific error cases
        if (
          parsedError.error?.includes("solc is not installed") ||
          parsedError.error?.includes("No solc version set")
        ) {
          throw new Error(
            `Solidity compiler setup required for versions: ${validVersions.join(", ")}. Please contact support.`
          )
        }

        throw new Error(
          `Analysis failed (${analysisResponse.status}): ${parsedError.error || analysisResponse.statusText}`
        )
      }

      const analysisData = await analysisResponse.json()

      // Group vulnerabilities by file and severity
      const vulnerabilitiesByFile = (analysisData.vulnerabilities || []).reduce(
        (acc: Record<string, Record<string, any[]>>, vuln: any) => {
          if (!vuln.elements?.[0]?.source_mapping?.filename_relative) {
            return acc
          }

          const file = vuln.elements[0].source_mapping.filename_relative
          if (!acc[file]) {
            acc[file] = {
              HIGH: [],
              MEDIUM: [],
              LOW: [],
              INFORMATIONAL: [],
            }
          }

          const impact = vuln.impact?.toUpperCase() || "INFORMATIONAL"
          if (acc[file][impact]) {
            acc[file][impact].push(vuln)
          }

          return acc
        },
        {}
      )

      // Update UI with Slither results first
      setAnalysisResult({
        ...analysisData,
        vulnerabilitiesByFile,
      })

      // Try RAG analysis separately
      try {
        // Read all files first
        const fileContents = await Promise.all(
          files.map(async (file) => ({
            name: file.name,
            content: await file.text(),
          }))
        )

        const ragResponse = await fetch(`${apiUrl}/rag/analyze`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            code: fileContents,
          }),
        })

        if (ragResponse.ok) {
          const ragData: AnalysisResult["ragAnalysis"] = await ragResponse.json()
          setAnalysisResult((prev) =>
            prev
              ? {
                  ...prev,
                  ragAnalysis: ragData,
                }
              : null
          )
        } else {
          const errorBody = await ragResponse.text()
          console.warn(
            `RAG analysis failed (${ragResponse.status}): ${ragResponse.statusText}${
              errorBody ? ` - ${errorBody}` : ""
            }`
          )
        }
      } catch (ragErr) {
        console.warn("RAG analysis error:", ragErr)
        // Continue showing Slither results even if RAG fails
      }
    } catch (err) {
      console.error("Analysis error:", err)
      let errorMessage = err instanceof Error ? err.message : "An error occurred during analysis"
      setError(errorMessage)
    } finally {
      setIsUploading(false)
    }
  }, [files])

  const renderSeverityIcon = useCallback((severity: string) => {
    const upperSeverity = severity?.toUpperCase() ?? "UNKNOWN"
    switch (upperSeverity) {
      case "HIGH":
        return <FaExclamationTriangle className={styles.highSeverity} />
      case "MEDIUM":
        return <FaExclamationTriangle className={styles.mediumSeverity} />
      case "LOW":
        return <FaInfoCircle className={styles.lowSeverity} />
      default:
        return <FaInfoCircle className={styles.unknownSeverity} />
    }
  }, [])

  const getRelevanceClass = (score: number) => {
    if (score >= 81) return styles.high
    if (score >= 61) return styles.good
    if (score >= 41) return styles.moderate
    if (score >= 21) return styles.low
    return styles.none
  }

  const getConfidenceClass = (score: number) => {
    if (score >= 80) return styles.high
    if (score >= 60) return styles.good
    if (score >= 40) return styles.moderate
    return styles.low
  }

  return (
    <Column spacing="l" className={styles.container}>
      <div
        className={`${styles.dropZone} ${isDragging ? styles.dragging : ""}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => document.getElementById("file-input")?.click()}
      >
        <input
          id="file-input"
          type="file"
          multiple
          accept=".sol"
          onChange={handleFileSelect}
          className={styles.fileInput}
        />
        <Column spacing="m" alignment={["center", "center"]}>
          <FaCloudUploadAlt className={styles.uploadIcon} />
          <Text>Drag and drop Solidity files here or click to select</Text>
          {files.length > 0 && (
            <Column spacing="s">
              <Text>Selected files:</Text>
              {files.map((f) => (
                <Row key={f.name} spacing="s" alignment={["start", "center"]}>
                  <Text>{f.name}</Text>
                  {fileVersions[f.name] && (
                    <Text size="small" className={styles.versionTag}>
                      v{fileVersions[f.name]}
                    </Text>
                  )}
                </Row>
              ))}
            </Column>
          )}
        </Column>
      </div>

      <Button disabled={files.length === 0 || isUploading} onClick={handleUpload} className={styles.analyzeButton}>
        {isUploading ? (
          <Row spacing="s" alignment={["center", "center"]}>
            <FaSpinner className={styles.spinner} />
            <Text>Analyzing...</Text>
          </Row>
        ) : (
          "Analyze Contracts"
        )}
      </Button>

      {error && (
        <Box className={styles.errorBox}>
          <Row spacing="s" alignment={["start", "center"]}>
            <FaExclamationTriangle className={styles.errorIcon} />
            <Text>{error}</Text>
          </Row>
        </Box>
      )}

      {analysisResult && (
        <Column spacing="l">
          <Box className={styles.resultsContainer}>
            <Column spacing="m">
              <Row spacing="s" alignment={["start", "center"]}>
                <FaCheckCircle className={styles.successIcon} />
                <Title variant="h4">Analysis Complete</Title>
              </Row>

              <Row className={styles.stats} spacing="l">
                <Column spacing="xs">
                  <Text strong>Risk Level</Text>
                  <Text className={`${styles.riskLevel} ${styles[analysisResult.overall_risk_level.toLowerCase()]}`}>
                    {analysisResult.overall_risk_level}
                  </Text>
                </Column>
                <Column spacing="xs">
                  <Text strong>Files Analyzed</Text>
                  <Text>{analysisResult.total_files_analyzed}</Text>
                </Column>
                <Column spacing="xs">
                  <Text strong>Total Vulnerabilities</Text>
                  <Text>{analysisResult.total_vulnerabilities}</Text>
                </Column>
              </Row>

              {/* Render Slither Analysis Results */}
              {Object.entries(analysisResult.vulnerabilitiesByFile || {}).map(([file, severities]) => (
                <Box key={file} className={styles.fileResults}>
                  <Column spacing="m">
                    {Object.entries(severities).map(
                      ([severity, vulns]) =>
                        vulns.length > 0 && (
                          <Column key={severity} spacing="s">
                            <Text strong className={styles[severity.toLowerCase()]}>
                              {severity} Severity ({vulns.length})
                            </Text>
                            {vulns.map((vuln: any, index: number) => (
                              <Box key={index} className={styles.vulnerability}>
                                <Column spacing="xs">
                                  <Row spacing="s" alignment={["start", "center"]}>
                                    {renderSeverityIcon(severity)}
                                    <Text strong>{vuln.check}</Text>
                                  </Row>
                                  <Text>{vuln.description}</Text>
                                </Column>
                              </Box>
                            ))}
                          </Column>
                        )
                    )}
                  </Column>
                </Box>
              ))}
            </Column>
          </Box>

          {/* Render RAG Analysis Results in a separate section */}
          {analysisResult.ragAnalysis && (
            <Box className={styles.resultsContainer}>
              <Column spacing="m">
                <Title variant="h4">AI-Powered Analysis</Title>
                <Text>Based on analysis of similar vulnerabilities in other smart contracts</Text>

                {analysisResult.ragAnalysis.files.map((fileAnalysis, fileIndex) => (
                  <Column key={fileIndex} spacing="m">
                    <Title variant="h4">{fileAnalysis.file_name}</Title>
                    <Text>{fileAnalysis.analysis_summary}</Text>

                    {fileAnalysis.analyzed_documents.length > 0 && (
                      <Column spacing="m">
                        <Title variant="h4">Similar Vulnerabilities Found</Title>
                        {fileAnalysis.analyzed_documents
                          .filter((doc) => doc.evaluation.relevance_score > 0)
                          .map((doc, index) => (
                            <Box key={index} className={styles.vulnerability}>
                              <Column spacing="s">
                                <Row spacing="s" alignment={["start", "center"]}>
                                  {renderSeverityIcon(doc.metadata.severity)}
                                  <Column spacing="xs">
                                    <Text strong>{doc.metadata.category}</Text>
                                    <Text
                                      size="small"
                                      className={`${styles.relevanceScore} ${getRelevanceClass(doc.similarity.score)}`}
                                    >
                                      Similarity: {(doc.similarity.score * 100).toFixed(1)}%
                                    </Text>
                                  </Column>
                                </Row>

                                <Text>{doc.evaluation.explanation}</Text>

                                {doc.evaluation.affected_regions && doc.evaluation.affected_regions.length > 0 && (
                                  <Column spacing="xs">
                                    <Text size="small" strong>
                                      Affected Code:
                                    </Text>
                                    <div className={styles.codeBlock}>
                                      <code>{doc.evaluation.affected_regions.join("\n")}</code>
                                    </div>
                                  </Column>
                                )}

                                <Box className={styles.vulnMetadata}>
                                  <Column spacing="xs">
                                    <Text size="small" strong>
                                      Similar vulnerability found in:
                                    </Text>
                                    <Text size="small">{doc.metadata.repo_name}</Text>
                                    <Text size="small">{doc.metadata.file_path}</Text>
                                    {doc.content.code_snippet && (
                                      <div className={styles.codeBlock}>
                                        <code>{doc.content.code_snippet}</code>
                                      </div>
                                    )}
                                  </Column>
                                </Box>

                                <Text
                                  size="small"
                                  className={`${styles.relevanceScore} ${getRelevanceClass(
                                    doc.evaluation.relevance_score
                                  )}`}
                                >
                                  Relevance: {doc.evaluation.relevance_score.toFixed(1)}%
                                </Text>
                                <Text
                                  size="small"
                                  className={`${styles.confidenceScore} ${getConfidenceClass(
                                    doc.evaluation.confidence
                                  )}`}
                                >
                                  Confidence: {(Number(doc.evaluation.confidence) || 0).toFixed(1)}%
                                </Text>
                              </Column>
                            </Box>
                          ))}
                      </Column>
                    )}

                    <Column spacing="s">
                      <Title variant="h4">Risk Distribution</Title>
                      <Row spacing="m">
                        <Text>High: {fileAnalysis.statistics.risk_level_distribution.HIGH}</Text>
                        <Text>Medium: {fileAnalysis.statistics.risk_level_distribution.MEDIUM}</Text>
                        <Text>Low: {fileAnalysis.statistics.risk_level_distribution.LOW}</Text>
                      </Row>
                    </Column>
                  </Column>
                ))}
              </Column>
            </Box>
          )}
        </Column>
      )}
    </Column>
  )
}
