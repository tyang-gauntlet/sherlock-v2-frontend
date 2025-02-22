import React, { useCallback, useEffect } from "react"
import { Route, Routes, Navigate } from "react-router-dom"
import { ReactQueryDevtools } from "react-query/devtools"

import { FundraisingClaimPage } from "./pages/FundraisingClaim"
import { StakingPage } from "./pages/Staking"
import { StakingPositionsPage } from "./pages/StakingPositions"
import { USForbiddenPage } from "./pages/USForbidden"
import { OverviewPage } from "./pages/Overview"
import { ProtocolPage } from "./pages/Protocol"
import { ClaimsPage } from "./pages/Claim"
import AppStakers from "./AppStakers"
import AppProtocols from "./AppProtocols"
import AppAdmin from "./AppAdmin"
import { AppContests } from "./AppContests"
import AppProtocolDashboard from "./AppProtocolDashboard"

import { routes, protocolsRoutes, contestsRoutes, protocolDashboardRoutes, adminRoutes } from "./utils/routes"
import MobileBlock from "./components/MobileBlock/MobileBlock"
import { InternalOverviewPage } from "./pages/InternalOverview/InternalOverview"
import { ContestsPage } from "./pages/Contests"
import { ContestDetails } from "./pages/ContestDetails"
import { Leaderboard } from "./pages/Leaderboard"
import { AuditorProfile } from "./pages/AuditorProfile"
import { AuthenticationGate } from "./components/AuthenticationGate"
import { useAccount } from "wagmi"
import { useAuthentication } from "./hooks/api/useAuthentication"
import { ProtocolTeam } from "./pages/ProtocolTeam/ProtocolTeam"
import { AdminContestsList } from "./pages/admin/AdminContestsList/AdminContestsList"
import { AdminScope } from "./pages/admin/AdminScope/AdminScope"
import { AuditScope } from "./pages/AuditScope/AuditScope"
import { InitialPayment } from "./pages/protocol_dashboard/InitialPayment/InitialPayment"
import { FinalPayment } from "./pages/protocol_dashboard/FinalPayment/FinalPayment"
import { ContextQuestions } from "./pages/protocol_dashboard/ContextQuestions/ContextQuestions"
import { AIPage } from "./pages/AI/AI"

function App() {
  const { address: connectedAddress } = useAccount()
  const { signOut, profile } = useAuthentication()

  const addressIsAllowed = useCallback(
    (address: string) => profile?.addresses.some((a) => a.address === address),
    [profile]
  )

  useEffect(() => {
    if (profile && connectedAddress && !addressIsAllowed(connectedAddress)) {
      signOut()
    }
  }, [connectedAddress, addressIsAllowed, signOut, profile])

  return (
    <>
      <Routes>
        {/** Stakers section routes */}
        <Route path="/*" element={<AppStakers />}>
          <Route path={routes.Stake} element={<StakingPage />} />
          <Route path={routes.Overview} element={<OverviewPage />} />
          <Route path={routes.Positions} element={<StakingPositionsPage />} />
          <Route path={routes.Claim} element={<FundraisingClaimPage />} />
          <Route path={routes.USForbidden} element={<USForbiddenPage />} />

          <Route path="*" element={<Navigate replace to={`/${routes.Overview}`} />} />
        </Route>

        {/** Protocols section routes */}
        <Route path={`${routes.Protocols}/*`} element={<AppProtocols />}>
          <Route path={protocolsRoutes.Balance} element={<ProtocolPage />} />
          <Route path={protocolsRoutes.Claims} element={<ClaimsPage />} />

          <Route path={"balance/:protocolTag"} element={<ProtocolPage />} />

          <Route path="*" element={<Navigate replace to={protocolsRoutes.Balance} />} />
        </Route>

        {/** Protocol Dashboard section routes */}
        <Route path={`${routes.ProtocolDashboard}/*`} element={<AppProtocolDashboard />}>
          <Route path={protocolDashboardRoutes.InitialPayment} element={<InitialPayment />} />
          <Route path={protocolDashboardRoutes.Team} element={<ProtocolTeam />} />
          <Route path={protocolDashboardRoutes.FinalPayment} element={<FinalPayment />} />
          <Route path={protocolDashboardRoutes.Scope} element={<AuditScope />} />
          <Route path={protocolDashboardRoutes.Context} element={<ContextQuestions />} />
        </Route>

        {/** Audit Contests section routes */}
        <Route path={`${routes.AuditContests}/*`} element={<AppContests />}>
          <Route path={contestsRoutes.Contests} element={<ContestsPage />} />
          <Route path={contestsRoutes.ContestDetails} element={<ContestDetails />} />
          <Route path={contestsRoutes.Leaderboard} element={<Leaderboard />} />
          <Route path={contestsRoutes.AI} element={<AIPage />} />

          <Route
            path="scoreboard"
            element={<Navigate to={`/${routes.AuditContests}/${contestsRoutes.Leaderboard}`} />}
          />

          <Route
            path={contestsRoutes.Profile}
            element={
              <AuthenticationGate redirectRoute={routes.AuditContests}>
                <AuditorProfile />
              </AuthenticationGate>
            }
          />

          <Route path="*" element={<Navigate replace to={contestsRoutes.Contests} />} />
        </Route>

        {/** Internal section routes */}
        <Route path={`${routes.Admin}/*`} element={<AppAdmin />}>
          <Route path={adminRoutes.InternalOverview} element={<InternalOverviewPage />} />
          <Route path={adminRoutes.Contests} element={<AdminContestsList />} />
          <Route path={adminRoutes.Scope} element={<AdminScope />} />

          <Route path="*" element={<Navigate replace to={adminRoutes.InternalOverview} />} />
        </Route>

        <Route path="/scope" element={<AuditScope />} />

        <Route path="*" element={<Navigate replace to="/" />} />
      </Routes>

      <MobileBlock />
      <ReactQueryDevtools initialIsOpen={false} position="bottom-right" />
    </>
  )
}

export default App
