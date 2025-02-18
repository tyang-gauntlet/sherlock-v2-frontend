import React from "react"
import { Box } from "../../components/Box"
import { Column, Row } from "../../components/Layout"
import { Title } from "../../components/Title"
import { Text } from "../../components/Text"
import { CodeUploader } from "./components/CodeUploader"
import { FaShieldAlt, FaRobot, FaClock, FaDollarSign } from "react-icons/fa"

import styles from "./AI.module.scss"

export const AIPage: React.FC = () => {
  return (
    <Column spacing="xl" className={styles.container}>
      <Box shadow={false}>
        <Column spacing="xl">
          <Column spacing="s">
            <div className={styles.heroText}>
              <Title variant="h2">Smarter Smart Contracts with AI</Title>
            </div>
            <Text size="large">Enhance your smart contract security with AI-powered analysis before your audit</Text>
          </Column>

          <div className={styles.featuresGrid}>
            <div className={styles.featureCard}>
              <Row spacing="s" alignment={["start", "center"]}>
                <FaShieldAlt className={styles.icon} />
                <Text strong>Proactive Security</Text>
              </Row>
              <Text>Detect vulnerabilities early with AI-driven analysis</Text>
            </div>

            <div className={styles.featureCard}>
              <Row spacing="s" alignment={["start", "center"]}>
                <FaClock className={styles.icon} />
                <Text strong>Save Time</Text>
              </Row>
              <Text>Get instant insights into your code's security posture</Text>
            </div>

            <div className={styles.featureCard}>
              <Row spacing="s" alignment={["start", "center"]}>
                <FaDollarSign className={styles.icon} />
                <Text strong>Reduce Costs</Text>
              </Row>
              <Text>Fix issues before the audit, save on revisions</Text>
            </div>

            <div className={styles.featureCard}>
              <Row spacing="s" alignment={["start", "center"]}>
                <FaRobot className={styles.icon} />
                <Text strong>AI-Powered</Text>
              </Row>
              <Text>Leveraging advanced RAG and pattern analysis</Text>
            </div>
          </div>
        </Column>
      </Box>

      <Box shadow={false}>
        <Column spacing="m">
          <Title variant="h3">Code Analysis</Title>
          <Text>Upload your Solidity smart contracts for AI-powered analysis and vulnerability detection</Text>
          <CodeUploader />
        </Column>
      </Box>
    </Column>
  )
}
