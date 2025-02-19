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
  files: Array<{
    file_name: string
    contracts: Array<{
      name: string
      functions: Array<{
        name: string
        visibility: string
        modifiers: string[]
        parameters: Array<{
          name: string
          type: string
        }>
      }>
      state_variables: Array<{
        name: string
        type: string
        visibility: string
      }>
      vulnerabilities: Array<{
        type: string
        severity: string
        description: string
        line?: number
        contract?: string
        function?: string
      }>
      suggestions: Array<{
        type: string
        severity: string
        description: string
        line?: number
        contract?: string
      }>
    }>
    risk_level: string
    error?: string
  }>
  overall_risk_level: string
  total_contracts: number
  total_functions: number
  vulnerabilities: Array<{
    type: string
    severity: string
    description: string
    line?: number
    contract?: string
    function?: string
  }>
  suggestions: Array<{
    type: string
    severity: string
    description: string
    line?: number
    contract?: string
  }>
}

export const CodeUploader: React.FC = () => {
  const [isDragging, setIsDragging] = useState(false)
  const [isUploading, setIsUploading] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const sortBySeverity = useCallback((a: { severity: string }, b: { severity: string }) => {
    const severityOrder: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 }
    return (severityOrder[a.severity.toUpperCase()] ?? 3) - (severityOrder[b.severity.toUpperCase()] ?? 3)
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
      const response = await fetch(`${apiUrl}/analyze`, {
        method: "POST",
        body: formData,
      })

      if (!response.ok) {
        throw new Error("Upload failed")
      }

      const result = await response.json()
      setAnalysisResult(result)
      setFiles([])
    } catch (error) {
      setError(error instanceof Error ? error.message : "An error occurred")
      console.error("Upload error:", error)
    } finally {
      setIsUploading(false)
    }
  }, [files])

  const renderSeverityIcon = useCallback((severity: string) => {
    switch (severity.toUpperCase()) {
      case "HIGH":
        return <FaExclamationTriangle className={styles.highSeverity} />
      case "MEDIUM":
        return <FaExclamationTriangle className={styles.mediumSeverity} />
      case "LOW":
        return <FaInfoCircle className={styles.lowSeverity} />
      default:
        return null
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
        >
          <Column spacing="m" alignment="center">
            <FaCloudUploadAlt size={48} />
            <Text>Drag and drop Solidity files or click to select</Text>
            <input
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
            <Row spacing="s" alignment={["start", "center"]}>
              {renderSeverityIcon(analysisResult.overall_risk_level)}
              <Title variant="h3">Analysis Results</Title>
            </Row>

            <Column spacing="m">
              <Text strong>Overview</Text>
              <Row spacing="xl">
                <Text>Total Contracts: {analysisResult.total_contracts}</Text>
                <Text>Total Functions: {analysisResult.total_functions}</Text>
                <Row spacing="m">
                  <Text className={styles.highSeverity}>
                    High: {analysisResult.vulnerabilities.filter((v) => v.severity.toUpperCase() === "HIGH").length}
                  </Text>
                  <Text className={styles.mediumSeverity}>
                    Medium: {analysisResult.vulnerabilities.filter((v) => v.severity.toUpperCase() === "MEDIUM").length}
                  </Text>
                  <Text className={styles.lowSeverity}>
                    Low: {analysisResult.vulnerabilities.filter((v) => v.severity.toUpperCase() === "LOW").length}
                  </Text>
                </Row>
              </Row>
            </Column>

            <Column spacing="s">
              <Text strong>Analyzed Files</Text>
              {analysisResult.files.map((file, index) => (
                <Box key={index} shadow={false} className={styles.vulnerabilityCard}>
                  <Column spacing="xs">
                    <Row spacing="xs" alignment={["start", "center"]}>
                      {renderSeverityIcon(file.risk_level)}
                      <Text strong>{file.file_name}</Text>
                    </Row>

                    {file.error ? (
                      <Text size="small" className={styles.highSeverity}>
                        {file.error}
                      </Text>
                    ) : (
                      <>
                        <Text size="small" className={styles.contractCount}>
                          {file.contracts.length > 1 ? `${file.contracts.length} Contracts:` : "1 Contract:"}
                        </Text>
                        {file.contracts.map((contract, cIndex) => (
                          <Row key={cIndex} spacing="m" alignment={["start", "center"]}>
                            <Text strong size="small">
                              {contract.name}
                            </Text>
                            <Text size="small">
                              ({contract.functions.length} functions, {contract.state_variables.length} variables)
                            </Text>
                          </Row>
                        ))}
                      </>
                    )}
                  </Column>
                </Box>
              ))}
            </Column>

            {analysisResult.vulnerabilities.length > 0 && (
              <Column spacing="s">
                <Text strong>Vulnerabilities</Text>
                {[...analysisResult.vulnerabilities].sort(sortBySeverity).map((vuln, index) => (
                  <Box key={index} shadow={false} className={styles.vulnerabilityCard}>
                    <Row spacing="xs" alignment={["start", "center"]}>
                      {renderSeverityIcon(vuln.severity)}
                      <Column spacing="xs">
                        <Row spacing="xs" alignment={["start", "center"]}>
                          <Text strong>{vuln.type}</Text>
                          <Text className={styles[`${vuln.severity.toLowerCase()}Severity`]}>({vuln.severity})</Text>
                          {vuln.line && <Text size="small">Line {vuln.line}</Text>}
                        </Row>
                        <Row spacing="xs">
                          <Text size="small">{vuln.description}</Text>
                        </Row>
                        {(vuln.contract || vuln.function) && (
                          <Row spacing="xs">
                            <Text size="small" strong>
                              Location:{" "}
                            </Text>
                            <Text size="small">
                              {vuln.contract && `Contract: ${vuln.contract}`}
                              {vuln.function && ` → Function: ${vuln.function}`}
                            </Text>
                          </Row>
                        )}
                      </Column>
                    </Row>
                  </Box>
                ))}
              </Column>
            )}

            {analysisResult.suggestions.length > 0 && (
              <Column spacing="s">
                <Text strong>Suggestions</Text>
                {analysisResult.suggestions.map((suggestion, index) => (
                  <Box key={index} shadow={false} className={styles.vulnerabilityCard}>
                    <Row spacing="xs" alignment={["start", "center"]}>
                      <FaInfoCircle className={styles.lowSeverity} />
                      <Column spacing="xs">
                        <Row spacing="xs" alignment={["start", "center"]}>
                          <Text strong>{suggestion.type}</Text>
                          <Text className={styles.lowSeverity}>(Suggestion)</Text>
                          {suggestion.line && <Text size="small">Line {suggestion.line}</Text>}
                        </Row>
                        <Row spacing="xs">
                          <Text size="small">{suggestion.description}</Text>
                        </Row>
                        {suggestion.contract && (
                          <Row spacing="xs">
                            <Text size="small" strong>
                              Location:{" "}
                            </Text>
                            <Text size="small">Contract: {suggestion.contract}</Text>
                          </Row>
                        )}
                      </Column>
                    </Row>
                  </Box>
                ))}
              </Column>
            )}
          </Column>
        </Box>
      )}
    </Column>
  )
}
