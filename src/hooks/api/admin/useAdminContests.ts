import { useQuery } from "react-query"
import { contests as contestsAPI } from "../axios"

import { getAdminContests as getAdminContestsUrl } from "../urls"

export type ContestStatus = "DRAFT" | "CREATED" | "RUNNING" | "JUDGING" | "FINISHED" | "ESCALATING" | "SHERLOCK_JUDGING"

export type ContestsListItem = {
  id: number
  title: string
  shortDescription: string
  logoURL: string
  status: ContestStatus
  initialPayment: boolean
  fullPaymentComplete: boolean
  adminUpcomingApproved: boolean
  adminStartApproved: boolean
  dashboardID?: string
  startDate: number
  endDate: number
  submissionReady: boolean
  hasSolidityMetricsReport: boolean
  leadSeniorAuditorHandle: string
  leadSeniorAuditorFixedPay: number | null
  leadSeniorSelectionMessageSentAt: number
  leadSeniorSelectionDate: number
  leadSeniorConfirmationMessage: string
  auditReport?: string
  nSLOC?: number
  expectedNSLOC?: number
  rewards: number
  judgingPrizePool: number
  leadJudgeFixedPay: number
  fullPayment: number
  initialScopeSubmitted: boolean
  initialScopeSubmittedAt: number | null
  finalScopeSubmitted: boolean
  telegramChat?: string
  finalReportAvailable?: boolean
  lswPaymentStructure: "TIERED" | "BEST_EFFORTS" | "FIXED"
  customLswFixedPay: number | null
  private: boolean
  requiresKYC: boolean
  maxNumberOfParticipants: number | null
  token: string
}

export type GetAdminContestsResponse = {
  id: number
  title: string
  short_description: string
  logo_url: string
  status: ContestStatus
  initial_payment_complete: boolean
  full_payment_complete: boolean
  admin_upcoming_approved: boolean
  admin_start_approved: boolean
  dashboard_id: string
  starts_at: number
  ends_at: number
  protocol_submission_ready: boolean
  has_solidity_metrics_report: boolean
  lead_senior_auditor_handle: string
  senior_selection_message_sent_at: number
  senior_selection_date: number
  senior_confirmed_message: string
  audit_report?: string
  nsloc?: number
  expected_nsloc?: number
  audit_rewards: number
  judging_prize_pool: number
  lead_judge_fixed_pay: number
  full_payment: number
  initial_scope_submitted: boolean
  initial_scope_submitted_at: number | null
  final_scope_submitted: boolean
  telegram_chat?: string
  final_report_available?: boolean
  lsw_payment_structure: "TIERED" | "BEST_EFFORTS" | "FIXED"
  lead_senior_auditor_fixed_pay: number | null
  private: boolean
  requires_kyc: boolean
  max_number_of_participants: number | null
  token: string
}

export type ContestListStatus = "active" | "finished" | "draft"

export const parseContest = (d: GetAdminContestsResponse): ContestsListItem => {
  return {
    id: d.id,
    title: d.title,
    shortDescription: d.short_description,
    logoURL: d.logo_url,
    status: d.status,
    initialPayment: d.initial_payment_complete,
    fullPaymentComplete: d.full_payment_complete,
    adminUpcomingApproved: d.admin_upcoming_approved,
    adminStartApproved: d.admin_start_approved,
    dashboardID: d.dashboard_id,
    startDate: d.starts_at,
    endDate: d.ends_at,
    submissionReady: d.protocol_submission_ready,
    hasSolidityMetricsReport: d.has_solidity_metrics_report,
    leadSeniorAuditorHandle: d.lead_senior_auditor_handle,
    leadSeniorSelectionMessageSentAt: d.senior_selection_message_sent_at,
    leadSeniorSelectionDate: d.senior_selection_date,
    leadSeniorConfirmationMessage: d.senior_confirmed_message,
    auditReport: d.audit_report,
    rewards: d.audit_rewards,
    judgingPrizePool: d.judging_prize_pool,
    leadJudgeFixedPay: d.lead_judge_fixed_pay,
    fullPayment: d.full_payment,
    initialScopeSubmitted: d.initial_scope_submitted,
    initialScopeSubmittedAt: d.initial_scope_submitted_at,
    finalScopeSubmitted: d.final_scope_submitted,
    nSLOC: d.nsloc,
    telegramChat: d.telegram_chat,
    finalReportAvailable: d.final_report_available,
    lswPaymentStructure: d.lsw_payment_structure,
    customLswFixedPay: d.lead_senior_auditor_fixed_pay,
    private: d.private,
    requiresKYC: d.requires_kyc,
    maxNumberOfParticipants: d.max_number_of_participants,
    leadSeniorAuditorFixedPay: d.lead_senior_auditor_fixed_pay,
    token: d.token,
  }
}

export const adminContestsQuery = (status: ContestListStatus) => ["admin-contests", status]
export const useAdminContests = (status: ContestListStatus) =>
  useQuery<ContestsListItem[], Error>(adminContestsQuery(status), async () => {
    const { data } = await contestsAPI.get<GetAdminContestsResponse[]>(getAdminContestsUrl(status))

    return data.map(parseContest)
  })
