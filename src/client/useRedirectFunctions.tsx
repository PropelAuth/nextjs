import React, { useContext, useEffect } from "react"
import { AuthContext } from "./AuthProvider"

export function useRedirectFunctions() {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error("useRedirectFunctions must be used within an AuthProvider")
    }
    const {
        redirectToAccountPage,
        redirectToSignupPage,
        redirectToLoginPage,
        redirectToOrgPage,
        redirectToCreateOrgPage,
    } = context
    return {
        redirectToSignupPage,
        redirectToLoginPage,
        redirectToAccountPage,
        redirectToOrgPage,
        redirectToCreateOrgPage,
    }
}

export interface RedirectProps {
    children?: React.ReactNode
}

export function RedirectToSignup({ children }: RedirectProps) {
    const { redirectToSignupPage } = useRedirectFunctions()

    useEffect(() => {
        redirectToSignupPage()
    }, [])

    return <>{children}</>
}

export function RedirectToLogin({ children }: RedirectProps) {
    const { redirectToLoginPage } = useRedirectFunctions()
    useEffect(() => {
        redirectToLoginPage()
    }, [])
    return <>{children}</>
}
