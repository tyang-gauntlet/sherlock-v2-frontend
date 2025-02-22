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
      start_line?: number
      end_line?: number
      function?: string
      contract?: string
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
  batch_statistics: {
    similarity_stats: {
      mean: number
      median: number
      std_dev: number
      min: number
      max: number
    }
    relevance_stats: {
      mean: number
      median: number
      std_dev: number
      min: number
      max: number
    }
    confidence_stats: {
      mean: number
      median: number
      std_dev: number
      min: number
      max: number
    }
    total_documents_retrieved: number
    total_documents_analyzed: number
    risk_level_distribution: {
      HIGH: number
      MEDIUM: number
      LOW: number
      NONE: number
    }
    category_distribution: {
      [key: string]: {
        count: number
        avg_relevance: number
        avg_similarity: number
      }
    }
  }
  model_info: {
    embedding_model: string
    llm_model: string
    embedding_dimension: number
    timestamp: string
  }
  files?: Array<{
    file_name: string
    error?: string
    vulnerabilities?: Array<{
      type: string
      description: string
      severity: string
      confidence: string
      contract?: string
      function?: string
    }>
  }>
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
  }, [])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files).filter(
        (file) => file.name.endsWith(".sol") || file.type === "application/json"
      )
      setFiles(selectedFiles)
      setAnalysisResult(null)
      setError(null)
    }
  }, [])

  const handleUpload = useCallback(async () => {
    if (files.length === 0) return

    setIsUploading(true)
    setError(null)
    const formData = new FormData()
    files.forEach((file) => {
      formData.append("files", file)
    })

    try {
      const apiUrl = await getAPIURL()

      // First get the standard Slither analysis
      const analysisResponse = await fetch(`${apiUrl}/analyze`, {
        method: "POST",
        body: formData,
      })

      if (!analysisResponse.ok) {
        throw new Error("Analysis failed")
      }

      const analysisData = await analysisResponse.json()

      // Prepare RAG analysis for each file
      const ragPromises = []

      for (const file of files) {
        const fileContent = await file.text()

        // Analyze the whole file
        ragPromises.push(
          fetch(`${apiUrl}/rag/analyze`, {
            method: "POST",
            body: JSON.stringify({
              code: fileContent,
              context: `Full file analysis of ${file.name}`,
              scope: "file",
            }),
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
            },
          })
            .then((res) => {
              if (!res.ok) {
                throw new Error(`RAG analysis failed: ${res.statusText}`)
              }
              return res.json()
            })
            .catch((error) => {
              console.error("RAG analysis error:", error)
              return null
            })
        )
      }

      // Wait for all RAG analyses to complete
      const ragResults = await Promise.all(ragPromises)

      // Filter out failed results
      const validResults = ragResults.filter((result) => result !== null)

      if (validResults.length === 0) {
        throw new Error("All RAG analyses failed")
      }

      // Combine all analyzed documents
      const allAnalyzedDocuments = validResults.flatMap((result) => result.analyzed_documents || [])

      // Combine all batch statistics
      const combinedBatchStats = {
        similarity_stats: calculateCombinedStats(validResults.map((r) => r.batch_statistics?.similarity_stats)),
        relevance_stats: calculateCombinedStats(validResults.map((r) => r.batch_statistics?.relevance_stats)),
        confidence_stats: calculateCombinedStats(validResults.map((r) => r.batch_statistics?.confidence_stats)),
        total_documents_retrieved: validResults.reduce(
          (sum, r) => sum + (r.batch_statistics?.total_documents_retrieved || 0),
          0
        ),
        total_documents_analyzed: validResults.reduce(
          (sum, r) => sum + (r.batch_statistics?.total_documents_analyzed || 0),
          0
        ),
        risk_level_distribution: {
          HIGH: validResults.reduce((sum, r) => sum + (r.batch_statistics?.risk_level_distribution?.HIGH || 0), 0),
          MEDIUM: validResults.reduce((sum, r) => sum + (r.batch_statistics?.risk_level_distribution?.MEDIUM || 0), 0),
          LOW: validResults.reduce((sum, r) => sum + (r.batch_statistics?.risk_level_distribution?.LOW || 0), 0),
          NONE: validResults.reduce((sum, r) => sum + (r.batch_statistics?.risk_level_distribution?.NONE || 0), 0),
        },
        category_distribution: combineCategoryDistributions(
          validResults.map((r) => r.batch_statistics?.category_distribution)
        ),
      }

      // Set the analysis result with both Slither and RAG results
      setAnalysisResult({
        analysis_summary: validResults[0]?.analysis_summary || "",
        analyzed_documents: allAnalyzedDocuments,
        batch_statistics: combinedBatchStats,
        model_info: validResults[0]?.model_info || {
          embedding_model: "sentence-transformers/all-mpnet-base-v2",
          llm_model: "gpt-4",
          embedding_dimension: 768,
          timestamp: new Date().toISOString(),
        },
        files: analysisData.files, // Include Slither analysis results
      })
      setFiles([])
    } catch (error) {
      setError(error instanceof Error ? error.message : "An error occurred")
      console.error("Upload error:", error)
    } finally {
      setIsUploading(false)
    }
  }, [files])

  // Helper function to calculate combined statistics
  const calculateCombinedStats = (
    statsArray: Array<{ mean: number; median: number; std_dev: number; min: number; max: number } | undefined>
  ) => {
    const validStats = statsArray.filter((s): s is NonNullable<typeof s> => s !== undefined)
    if (validStats.length === 0) {
      return { mean: 0, median: 0, std_dev: 0, min: 0, max: 0 }
    }
    return {
      mean: validStats.reduce((sum, s) => sum + s.mean, 0) / validStats.length,
      median: validStats.reduce((sum, s) => sum + s.median, 0) / validStats.length,
      std_dev: validStats.reduce((sum, s) => sum + s.std_dev, 0) / validStats.length,
      min: Math.min(...validStats.map((s) => s.min)),
      max: Math.max(...validStats.map((s) => s.max)),
    }
  }

  // Helper function to combine category distributions
  const combineCategoryDistributions = (
    distributions: Array<Record<string, { count: number; avg_relevance: number; avg_similarity: number }> | undefined>
  ) => {
    const combined: Record<string, { count: number; avg_relevance: number; avg_similarity: number }> = {}

    distributions.forEach((dist) => {
      if (!dist) return
      Object.entries(dist).forEach(([category, stats]) => {
        if (!combined[category]) {
          combined[category] = { count: 0, avg_relevance: 0, avg_similarity: 0 }
        }
        combined[category].count += stats.count
        combined[category].avg_relevance += stats.avg_relevance * stats.count
        combined[category].avg_similarity += stats.avg_similarity * stats.count
      })
    })

    // Normalize averages
    Object.values(combined).forEach((stats) => {
      if (stats.count > 0) {
        stats.avg_relevance /= stats.count
        stats.avg_similarity /= stats.count
      }
    })

    return combined
  }

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

  return (
    <Column spacing="xl">
      <Column spacing="m">
        <div
          className={`${styles.dropzone} ${isDragging ? styles.dragging : ""}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => document.getElementById("file-input")?.click()}
        >
          <Column spacing="m" alignment="center">
            <FaCloudUploadAlt size={48} />
            <Text>Drag and drop Solidity files or click to select</Text>
            <input
              id="file-input"
              type="file"
              accept=".sol,application/json"
              multiple
              onChange={handleFileSelect}
              className={styles.fileInput}
            />
          </Column>
        </div>

        {files.length > 0 && (
          <Column spacing="m">
            <Text strong>Selected files:</Text>
            {files.map((file, index) => (
              <Text key={index} size="small">
                {file.name}
              </Text>
            ))}
            <Row>
              <Button onClick={handleUpload} disabled={isUploading}>
                {isUploading ? (
                  <>
                    <FaSpinner className={styles.spinner} />
                    Analyzing...
                  </>
                ) : (
                  "Analyze Code"
                )}
              </Button>
            </Row>
          </Column>
        )}

        {error && (
          <Box shadow={false}>
            <Row spacing="s" alignment={["start", "center"]}>
              <FaExclamationTriangle />
              <Text>{error}</Text>
            </Row>
          </Box>
        )}
      </Column>

      {analysisResult && (
        <Box shadow={false} fullWidth>
          <Column spacing="l">
            <Title variant="h3">Analysis Results</Title>

            {/* Slither Static Analysis Results */}
            <Column spacing="m">
              <Box shadow={false} className={styles.terminalOutput}>
                {analysisResult.files?.map((file, fileIndex) => (
                  <Column key={fileIndex} spacing="s">
                    <Text strong>{file.file_name}</Text>
                    {file.error ? (
                      <Text className={styles.error}>{file.error}</Text>
                    ) : (
                      <div className={styles.vulnGroups}>
                        {["HIGH", "MEDIUM", "LOW"].map((severity) => {
                          const vulnsForSeverity =
                            file.vulnerabilities?.filter((v) => v.severity.toUpperCase() === severity) || []

                          if (vulnsForSeverity.length === 0) return null

                          return (
                            <div key={severity} className={styles.vulnGroup}>
                              <div className={`${styles.vulnGroupHeader} ${styles[severity.toLowerCase()]}`}>
                                <span className={styles.vulnCount}>{vulnsForSeverity.length}</span>
                                <Text strong>{severity}</Text>
                              </div>
                              {vulnsForSeverity.map((vuln, vulnIndex) => {
                                // Extract line numbers from description if present
                                const lineMatch = vuln.description.match(/\.sol#(\d+-\d+|\d+)/)
                                const lineInfo = lineMatch ? `#${lineMatch[1]}` : ""

                                // Split description into text and code parts
                                const codeMatch = vuln.description.match(/"([^"]+)"/)
                                const code = codeMatch ? codeMatch[1] : ""
                                const description = vuln.description
                                  .replace(/\([^)]*\.sol#[^)]*\)/g, "")
                                  .replace(/"[^"]*"/, "")
                                  .replace(/\s+/g, " ")
                                  .trim()

                                return (
                                  <div key={vulnIndex} className={styles.vulnDetails}>
                                    <div className={styles.vulnTitle}>
                                      <div className={styles.vulnTitleMain}>
                                        <Text strong>{vuln.type}</Text>
                                        {lineInfo && <span className={styles.lineInfo}>{lineInfo}</span>}
                                      </div>
                                      <span className={styles.vulnConfidence}>{vuln.confidence}</span>
                                    </div>
                                    <div className={styles.vulnDescription}>{description}</div>
                                    {code && (
                                      <div className={styles.codeBlock}>
                                        <code>{code}</code>
                                      </div>
                                    )}
                                  </div>
                                )
                              })}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </Column>
                ))}
              </Box>
            </Column>

            {/* RAG Analysis Results */}
            <Column spacing="m">
              <Title variant="h4">AI-Powered Analysis</Title>
              <Box shadow={false} className={styles.terminalOutput}>
                <Column spacing="m">
                  {/* Analysis Summary Section */}
                  <div className={styles.analysisSection}>
                    <Text strong className={styles.sectionTitle}>
                      📊 Analysis Summary
                    </Text>
                    <div className={styles.analysisSummary}>
                      <Text>{analysisResult.analysis_summary}</Text>
                    </div>
                  </div>

                  {/* Vulnerability Analysis Section */}
                  <div className={styles.analysisSection}>
                    <Text strong className={styles.sectionTitle}>
                      🔍 Detailed Vulnerability Analysis
                    </Text>
                    {analysisResult.analyzed_documents
                      .sort((a, b) => b.evaluation.relevance_score - a.evaluation.relevance_score)
                      .map((doc, index) => {
                        const location =
                          doc.metadata.type === "function"
                            ? `Function ${doc.metadata.function} in ${doc.metadata.contract}`
                            : doc.metadata.type === "contract"
                            ? `Contract ${doc.metadata.contract}`
                            : `File ${doc.metadata.file_path}`

                        const riskLevelClass = `risk${doc.evaluation.risk_level}`

                        return (
                          <div key={index} className={styles.vulnAnalysis}>
                            <div className={`${styles.vulnHeader} ${styles[riskLevelClass]}`}>
                              <Text strong>📍 {location}</Text>
                              <span className={styles.riskBadge}>{doc.evaluation.risk_level}</span>
                            </div>
                            <div className={styles.vulnContent}>
                              <div className={styles.codeSnippet}>
                                <Text className={styles.snippetTitle}>Relevant Code:</Text>
                                <pre>
                                  <code>{doc.content.code_snippet}</code>
                                </pre>
                              </div>
                              <div className={styles.vulnDetails}>
                                <Text className={styles.vulnExplanation}>{doc.evaluation.explanation}</Text>
                                <div className={styles.vulnMetadata}>
                                  <div className={styles.metadataItem}>
                                    <Text strong>Affected Regions:</Text>
                                    <Text>{doc.evaluation.affected_regions.join(", ")}</Text>
                                  </div>
                                  <div className={styles.metadataStats}>
                                    <span className={styles.statItem}>
                                      Relevance: {Math.round(doc.evaluation.relevance_score * 100)}%
                                    </span>
                                    <span className={styles.statItem}>
                                      Confidence: {Math.round(doc.evaluation.confidence * 100)}%
                                    </span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        )
                      })}
                  </div>

                  {/* Analysis Statistics Section */}
                  <div className={styles.analysisSection}>
                    <Text strong className={styles.sectionTitle}>
                      📈 Analysis Statistics
                    </Text>
                    <div className={styles.statsGrid}>
                      <div className={styles.statCard}>
                        <Text strong>Documents Analyzed</Text>
                        <div className={styles.statValue}>
                          <Text>{analysisResult.batch_statistics.total_documents_analyzed}</Text>
                          <Text size="small" className={styles.statLabel}>
                            out of {analysisResult.batch_statistics.total_documents_retrieved} retrieved
                          </Text>
                        </div>
                      </div>

                      <div className={styles.statCard}>
                        <Text strong>Risk Distribution</Text>
                        <div className={styles.riskDistribution}>
                          <div className={styles.riskBar}>
                            <div
                              className={`${styles.riskSegment} ${styles.highRisk}`}
                              style={{
                                flex: analysisResult.batch_statistics.risk_level_distribution.HIGH || 0,
                              }}
                            >
                              <Text size="small">
                                HIGH: {analysisResult.batch_statistics.risk_level_distribution.HIGH || 0}
                              </Text>
                            </div>
                            <div
                              className={`${styles.riskSegment} ${styles.mediumRisk}`}
                              style={{
                                flex: analysisResult.batch_statistics.risk_level_distribution.MEDIUM || 0,
                              }}
                            >
                              <Text size="small">
                                MED: {analysisResult.batch_statistics.risk_level_distribution.MEDIUM || 0}
                              </Text>
                            </div>
                            <div
                              className={`${styles.riskSegment} ${styles.lowRisk}`}
                              style={{
                                flex: analysisResult.batch_statistics.risk_level_distribution.LOW || 0,
                              }}
                            >
                              <Text size="small">
                                LOW: {analysisResult.batch_statistics.risk_level_distribution.LOW || 0}
                              </Text>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className={styles.statCard}>
                        <Text strong>Similarity Scores</Text>
                        <div className={styles.scoreStats}>
                          <div className={styles.scoreStat}>
                            <Text size="small">
                              Mean: {(analysisResult.batch_statistics.similarity_stats.mean * 100).toFixed(1)}%
                            </Text>
                            <Text size="small">
                              Median: {(analysisResult.batch_statistics.similarity_stats.median * 100).toFixed(1)}%
                            </Text>
                          </div>
                        </div>
                      </div>

                      <div className={styles.statCard}>
                        <Text strong>Relevance Scores</Text>
                        <div className={styles.scoreStats}>
                          <div className={styles.scoreStat}>
                            <Text size="small">
                              Mean: {(analysisResult.batch_statistics.relevance_stats.mean * 100).toFixed(1)}%
                            </Text>
                            <Text size="small">
                              Median: {(analysisResult.batch_statistics.relevance_stats.median * 100).toFixed(1)}%
                            </Text>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className={styles.modelInfo}>
                      <Text strong>🤖 Model Information</Text>
                      <div className={styles.modelDetails}>
                        <Text size="small">Embedding Model: {analysisResult.model_info.embedding_model}</Text>
                        <Text size="small">LLM: {analysisResult.model_info.llm_model}</Text>
                      </div>
                    </div>
                  </div>
                </Column>
              </Box>
            </Column>
          </Column>
        </Box>
      )}
    </Column>
  )
}
