'use client'

import React, {useCallback, useEffect, useReducer} from "react"
import {User} from "../user"
import {doesLocalStorageMatch, hasWindow, isEqual, saveUserToLocalStorage, USER_INFO_KEY} from "./utils";
import {useRouter} from "next/navigation";

interface InternalAuthState {
    loading: boolean
    user?: User

    logout: () => Promise<void>

    redirectToLoginPage: () => void
    redirectToSignupPage: () => void
    redirectToAccountPage: () => void
    redirectToOrgPage: (orgId?: string) => void
    redirectToCreateOrgPage: () => void
    redirectToSetupSAMLPage: (orgId: string) => void

    getSignupPageUrl(): string

    getLoginPageUrl(): string

    getAccountPageUrl(): string

    getOrgPageUrl(orgId?: string): string

    getCreateOrgPageUrl(): string

    getSetupSAMLPageUrl(orgId: string): string

    refreshAuthInfo: () => Promise<User | undefined>
}

export type AuthProviderProps = {
    authUrl: string
    children?: React.ReactNode
}

export const AuthContext = React.createContext<InternalAuthState | undefined>(undefined)

type AuthState = {
    loading: boolean
    user?: User

    // There's no good way to trigger server components to reload outside of router.refresh()
    // This is our workaround until the app router has something better
    authChangeDetected: boolean
}

const initialAuthState = {
    loading: true,
    user: undefined,
    authChangeDetected: false,
}

type AuthStateAction = {
    user?: User
}

function authStateReducer(_state: AuthState, action: AuthStateAction): AuthState {
    const authChangeDetected = !_state.loading && !isEqual(action.user, _state.user)

    if (!action.user) {
        return {
            loading: false,
            user: undefined,
            authChangeDetected,
        }
    } else if (_state.loading) {
        return {
            loading: false,
            user: action.user,
            authChangeDetected,
        }
    } else {
        return {
            loading: false,
            user: action.user,
            authChangeDetected
        }
    }
}

export const AuthProvider = (props: AuthProviderProps) => {
    const [authState, dispatchInner] = useReducer(authStateReducer, initialAuthState)
    const router = useRouter()

    const dispatch = useCallback((action: AuthStateAction) => {
        dispatchInner(action)
        saveUserToLocalStorage(action.user)
    }, [dispatchInner])

    // This is because we don't have a good way to trigger server components to reload outside of router.refresh()
    // Once server actions isn't alpha, we can hopefully use that instead
    useEffect(() => {
        if (authState.authChangeDetected) {
            router.refresh()
        }
    }, [authState.authChangeDetected, router])

    // Trigger an initial refresh
    useEffect(() => {
        let didCancel = false

        async function refreshAuthInfo() {
            const {user} = await apiGetUserInfo()
            if (!didCancel) {
                dispatch({user})
            }
        }

        refreshAuthInfo()
        return () => {
            didCancel = true
        }
    }, [])


    // Periodically refresh the token
    useEffect(() => {
        let didCancel = false

        async function refreshToken() {
            const {user} = await apiGetUserInfo()
            if (!didCancel) {
                dispatch({user})
            }
        }

        async function onStorageEvent(event: StorageEvent) {
            if (event.key === USER_INFO_KEY && !doesLocalStorageMatch(event.newValue, authState.user)) {
                await refreshToken()
            }
        }

        // TODO: Retry logic if the request fails
        const interval = setInterval(refreshToken, 5 * 60 * 1000)

        if (hasWindow()) {
            window.addEventListener("storage", onStorageEvent)
            window.addEventListener("online", refreshToken)
            window.addEventListener("focus", refreshToken)
        }

        return () => {
            didCancel = true
            clearInterval(interval)
            if (hasWindow()) {
                window.removeEventListener("storage", onStorageEvent)
                window.removeEventListener("online", refreshToken)
                window.removeEventListener("focus", refreshToken)
            }
        }
    }, [dispatch, authState.user])


    const logout = useCallback(async () => {
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            credentials: "include",
        })
        dispatch({user: undefined})
    }, [dispatch])

    const getLoginPageUrl = () => "/api/auth/login"
    const getSignupPageUrl = () => "/api/auth/signup"
    const getAccountPageUrl = useCallback(() => {
        return `${props.authUrl}/account`
    }, [props.authUrl])
    const getOrgPageUrl = useCallback(
        (orgId?: string) => {
            if (orgId) {
                return `${props.authUrl}/org?id=${orgId}`
            } else {
                return `${props.authUrl}/org`
            }
        },
        [props.authUrl]
    )
    const getCreateOrgPageUrl = useCallback(() => {
        return `${props.authUrl}/create_org`
    }, [props.authUrl])

    const getSetupSAMLPageUrl = useCallback(
        (orgId: string) => {
            return `${props.authUrl}/saml?id=${orgId}`
        },
        [props.authUrl]
    )

    const redirectTo = (url: string) => {
        window.location.href = url
    }

    const redirectToLoginPage = () => redirectTo(getLoginPageUrl())
    const redirectToSignupPage = () => redirectTo(getSignupPageUrl())
    const redirectToAccountPage = () => redirectTo(getAccountPageUrl())
    const redirectToOrgPage = (orgId?: string) => redirectTo(getOrgPageUrl(orgId))
    const redirectToCreateOrgPage = () => redirectTo(getCreateOrgPageUrl())
    const redirectToSetupSAMLPage = (orgId: string) => redirectTo(getSetupSAMLPageUrl(orgId))

    const refreshAuthInfo = async () => {
        const {user} = await apiGetUserInfo()
        dispatch({user})
        return user
    }

    const value = {
        loading: authState.loading,
        user: authState.user,
        logout,
        redirectToLoginPage,
        redirectToSignupPage,
        redirectToAccountPage,
        redirectToOrgPage,
        redirectToCreateOrgPage,
        redirectToSetupSAMLPage,
        getLoginPageUrl,
        getSignupPageUrl,
        getAccountPageUrl,
        getOrgPageUrl,
        getCreateOrgPageUrl,
        getSetupSAMLPageUrl,
        refreshAuthInfo,
    }
    return <AuthContext.Provider value={value}>{props.children}</AuthContext.Provider>
}

type UserInfoResponse = { user?: User }

async function apiGetUserInfo(): Promise<UserInfoResponse> {
    try {
        const userInfoResponse = await fetch("/api/auth/userinfo", {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
            credentials: "include",
        })

        if (userInfoResponse.ok) {
            const userJson = await userInfoResponse.text()
            const user = User.fromJSON(userJson)
            return {user}
        } else if (userInfoResponse.status === 401) {
            return {user: undefined}
        } else {
            console.log("Failed to refresh token", userInfoResponse)
        }
    } catch (e) {
        console.log("Failed to refresh token", e)
    }
    throw new Error("Failed to refresh token")
}
