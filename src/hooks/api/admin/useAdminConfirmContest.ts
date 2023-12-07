import { DateTime } from "luxon"
import { useMutation, useQueryClient } from "react-query"
import { contests as contestsAPI } from "../axios"
import { adminConfirmContest as adminConfirmContestUrl } from "../urls"
import { AxiosError } from "axios"
import { adminContestsQuery } from "./useAdminContests"

type AdminConfirmContestParams = {
  id: number
  title: string
  shortDescription: string
  startDate: DateTime
  endDate: DateTime
  auditRewards: number
  judgingPrizePool: number
  leadJudgeFixedPay: number
  fullPayment: number
}

export const useAdminConfirmContest = () => {
  const queryClient = useQueryClient()
  const { mutate, mutateAsync, ...mutation } = useMutation<void, Error, AdminConfirmContestParams>(
    async (params) => {
      try {
        await contestsAPI.post(adminConfirmContestUrl(params.id), {
          title: params.title,
          short_description: params.shortDescription,
          starts_at: params.startDate.toSeconds(),
          ends_at: params.endDate.toSeconds(),
          audit_rewards: params.auditRewards,
          judging_prize_pool: params.judgingPrizePool,
          lead_judge_fixed_pay: params.leadJudgeFixedPay,
          full_payment: params.fullPayment,
        })
      } catch (error) {
        const axiosError = error as AxiosError
        throw Error(axiosError.response?.data.error ?? "Something went wrong. Please, try again.")
      }
    },
    {
      onSuccess: async () => {
        await queryClient.invalidateQueries(adminContestsQuery("draft"))
        await queryClient.invalidateQueries(adminContestsQuery("active"))
        await queryClient.invalidateQueries(adminContestsQuery("finished"))
      },
    }
  )

  return {
    confirmContest: mutate,
    ...mutation,
  }
}
