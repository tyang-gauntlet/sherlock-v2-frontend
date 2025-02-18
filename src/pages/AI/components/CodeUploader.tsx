import React, { useCallback, useState } from "react"
import { Box } from "../../../components/Box"
import { Button } from "../../../components/Button"
import { Column, Row } from "../../../components/Layout"
import { Text } from "../../../components/Text"
import { Title } from "../../../components/Title"
import { FaCloudUploadAlt, FaSpinner, FaExclamationTriangle, FaCheckCircle, FaInfoCircle } from "react-icons/fa"

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
      }>
      suggestions: Array<{
        type: string
        severity: string
        description: string
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
  }>
  suggestions: Array<{
    type: string
    severity: string
    description: string
  }>
}

export const CodeUploader: React.FC = () => {
  const [isDragging, setIsDragging] = useState(false)
  const [isUploading, setIsUploading] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

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
      const response = await fetch("http://localhost:5001/analyze", {
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
                <Text>Risk Level: {analysisResult.overall_risk_level}</Text>
              </Row>
            </Column>

            {analysisResult.vulnerabilities.length > 0 && (
              <Column spacing="m">
                <Text strong>Vulnerabilities</Text>
                {analysisResult.vulnerabilities.map((vuln, index) => (
                  <Box key={index} shadow={false}>
                    <Row spacing="s" alignment={["start", "center"]}>
                      {renderSeverityIcon(vuln.severity)}
                      <Column>
                        <Text strong>{vuln.type}</Text>
                        <Text>{vuln.description}</Text>
                      </Column>
                    </Row>
                  </Box>
                ))}
              </Column>
            )}

            {analysisResult.suggestions.length > 0 && (
              <Column spacing="m">
                <Text strong>Suggestions</Text>
                {analysisResult.suggestions.map((suggestion, index) => (
                  <Box key={index} shadow={false}>
                    <Row spacing="s" alignment={["start", "center"]}>
                      <FaInfoCircle />
                      <Column>
                        <Text strong>{suggestion.type}</Text>
                        <Text>{suggestion.description}</Text>
                      </Column>
                    </Row>
                  </Box>
                ))}
              </Column>
            )}

            {analysisResult.files.map((file, index) => (
              <Box key={index} shadow={false}>
                <Column spacing="m">
                  <Row spacing="s" alignment={["start", "center"]}>
                    {renderSeverityIcon(file.risk_level)}
                    <Text strong>{file.file_name}</Text>
                  </Row>

                  {file.error ? (
                    <Text>{file.error}</Text>
                  ) : (
                    file.contracts.map((contract, cIndex) => (
                      <Column key={cIndex} spacing="s">
                        <Text strong>{contract.name}</Text>
                        <Text>Functions: {contract.functions.length}</Text>
                        <Text>State Variables: {contract.state_variables.length}</Text>
                      </Column>
                    ))
                  )}
                </Column>
              </Box>
            ))}
          </Column>
        </Box>
      )}
    </Column>
  )
}
