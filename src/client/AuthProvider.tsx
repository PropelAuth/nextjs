'use client'

import React, { useCallback, useEffect, useReducer } from 'react'
import { useRouter } from 'next/navigation'
import { currentTimeSecs, hasWindow, isEqual } from './utils'
import { User } from './useUser'
import { toOrgIdToOrgMemberInfo } from '../user'

export interface RedirectToSignupOptions {
    postSignupRedirectPath?: string
    userSignupQueryParameters?: Record<string, string>
}
export interface RedirectToLoginOptions {
    postLoginRedirectPath?: string
    userSignupQueryParameters?: Record<string, string>
}
export interface RedirectOptions {
    redirectBackToUrl?: string
}

interface InternalAuthState {
    loading: boolean
    userAndAccessToken: UserAndAccessToken
    authUrl: string

    logout: () => Promise<void>

    redirectToLoginPage: (opts?: RedirectToLoginOptions) => void
    redirectToSignupPage: (opts?: RedirectToSignupOptions) => void
    redirectToAccountPage: (opts?: RedirectOptions) => void
    redirectToOrgPage: (orgId?: string, opts?: RedirectOptions) => void
    redirectToOrgSettingsPage: (orgId?: string, opts?: RedirectOptions) => void
    redirectToCreateOrgPage: (opts?: RedirectOptions) => void
    redirectToSetupSAMLPage: (orgId: string, opts?: RedirectOptions) => void
    redirectToOrgApiKeysPage: (orgId?: string, opts?: RedirectOptions) => void

    getSignupPageUrl(opts?: RedirectToSignupOptions): string
    getLoginPageUrl(opts?: RedirectToLoginOptions): string
    getAccountPageUrl(opts?: RedirectOptions): string
    getOrgPageUrl(orgId?: string, opts?: RedirectOptions): string
    getOrgSettingsPageUrl(orgId?: string, opts?: RedirectOptions): string
    getCreateOrgPageUrl(opts?: RedirectOptions): string
    getSetupSAMLPageUrl(orgId: string, opts?: RedirectOptions): string
    getOrgApiKeysPageUrl(orgId?: string, opts?: RedirectOptions): string

    refreshAuthInfo: () => Promise<User | undefined>
    setActiveOrg: (orgId: string) => Promise<User | undefined>
}

const DEFAULT_MIN_SECONDS_BEFORE_REFRESH = 120

export type AuthProviderProps = {
    authUrl: string
    reloadOnAuthChange?: boolean
    minSecondsBeforeRefresh?: number
    children?: React.ReactNode
    refreshOnFocus?: boolean
}

export const AuthContext = React.createContext<InternalAuthState | undefined>(undefined)

type UserAndAccessToken =
    | {
          user: User
          accessToken: string
      }
    | {
          user: undefined
          accessToken: undefined
      }

type AuthState = {
    loading: boolean
    userAndAccessToken: UserAndAccessToken

    // There's no good way to trigger server components to reload outside of router.refresh()
    // This is our workaround until the app router has something better
    authChangeDetected: boolean
}

const initialAuthState = {
    loading: true,
    userAndAccessToken: {
        user: undefined,
        accessToken: undefined,
    },
    authChangeDetected: false,
}

type AuthStateAction =
    | {
          user: User
          accessToken: string
      }
    | {
          user: undefined
          accessToken: undefined
      }

function authStateReducer(_state: AuthState, action: AuthStateAction): AuthState {
    const newUserForEqualityChecking = { ...action.user, lastActiveAt: undefined }
    const existingUserForEqualityChecking = { ..._state.userAndAccessToken.user, lastActiveAt: undefined }
    const authChangeDetected = !_state.loading && !isEqual(newUserForEqualityChecking, existingUserForEqualityChecking)

    if (!action.user) {
        return {
            loading: false,
            userAndAccessToken: {
                user: undefined,
                accessToken: undefined,
            },
            authChangeDetected,
        }
    } else if (_state.loading) {
        return {
            loading: false,
            userAndAccessToken: {
                user: action.user,
                accessToken: action.accessToken,
            },
            authChangeDetected,
        }
    } else {
        return {
            loading: false,
            userAndAccessToken: {
                user: action.user,
                accessToken: action.accessToken,
            },
            authChangeDetected,
        }
    }
}

export const AuthProvider = (props: AuthProviderProps) => {
    const [authState, dispatchInner] = useReducer(authStateReducer, initialAuthState)
    const [lastRefresh, setLastRefresh] = React.useState<number>(0)
    const router = useRouter()
    const reloadOnAuthChange = props.reloadOnAuthChange ?? true

    const dispatch = useCallback(
        (action: AuthStateAction) => {
            dispatchInner(action)
            setLastRefresh(currentTimeSecs())
        },
        [dispatchInner, setLastRefresh]
    )

    const shouldRefresh = useCallback(
        (lastRefresh: number) => {
            const minSecondsBeforeRefresh = props.minSecondsBeforeRefresh ?? DEFAULT_MIN_SECONDS_BEFORE_REFRESH
            return currentTimeSecs() - lastRefresh >= minSecondsBeforeRefresh
        },
        [props.minSecondsBeforeRefresh]
    )

    // This is because we don't have a good way to trigger server components to reload outside of router.refresh()
    useEffect(() => {
        if (reloadOnAuthChange && authState.authChangeDetected) {
            router.refresh()
        }
    }, [authState.authChangeDetected, reloadOnAuthChange, router])

    // Trigger an initial refresh
    useEffect(() => {
        let didCancel = false

        async function refreshAuthInfo() {
            const action = await apiGetUserInfo()
            if (!didCancel && !action.error) {
                dispatch(action)
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

        async function refreshAuthInfo() {
            if (!shouldRefresh(lastRefresh)) {
                return
            }

            const action = await apiGetUserInfo()
            if (!didCancel && !action.error) {
                dispatch(action)
            }
        }

        const interval = setInterval(refreshAuthInfo, 5 * 60 * 1000)
        return () => {
            didCancel = true
            clearInterval(interval)
        }
    }, [lastRefresh])

    const backgroundRefreshAuthInfo = useCallback(async () => {
        if (!shouldRefresh(lastRefresh)) {
            return
        }

        const action = await apiGetUserInfo()
        if (!action.error) {
            dispatch(action)
        }
    }, [lastRefresh])

    // Set up online and focus event listeners
    useEffect(() => {
        if (hasWindow()) {
            window.addEventListener('online', backgroundRefreshAuthInfo)

            // Default for refreshOnFocus is true
            if (props.refreshOnFocus !== false) {
                window.addEventListener('focus', backgroundRefreshAuthInfo)
            }
        }

        return () => {
            if (hasWindow()) {
                window.removeEventListener('online', backgroundRefreshAuthInfo)
                window.removeEventListener('focus', backgroundRefreshAuthInfo)
            }
        }
    }, [props.refreshOnFocus, backgroundRefreshAuthInfo])

    const logout = useCallback(async () => {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        })
        dispatch({ user: undefined, accessToken: undefined })
    }, [dispatch])

    const buildAuthPageUrl = (basePath: string, redirectPath?: string, queryParams?: Record<string, string>) => {
        let qs = new URLSearchParams()
        let url = basePath

        if (queryParams) {
            Object.entries(queryParams).forEach(([key, value]) => {
                qs.set(key, value)
            })
        }

        if (redirectPath) {
            qs.set('return_to_path', redirectPath)
        }

        if (qs.toString()) {
            url += `?${qs.toString()}`
        }

        return url
    }

    const getLoginPageUrl = (opts?: RedirectToLoginOptions) => {
        return buildAuthPageUrl('/api/auth/login', opts?.postLoginRedirectPath, opts?.userSignupQueryParameters)
    }

    const getSignupPageUrl = (opts?: RedirectToSignupOptions) => {
        return buildAuthPageUrl('/api/auth/signup', opts?.postSignupRedirectPath, opts?.userSignupQueryParameters)
    }
    const getAccountPageUrl = useCallback(
        (opts?: RedirectOptions) => {
            return addReturnToPath(`${props.authUrl}/account`, opts?.redirectBackToUrl)
        },
        [props.authUrl]
    )
    const getOrgPageUrl = useCallback(
        (orgId?: string, opts?: RedirectOptions) => {
            if (orgId) {
                return addReturnToPath(`${props.authUrl}/org?id=${orgId}`, opts?.redirectBackToUrl)
            } else {
                return addReturnToPath(`${props.authUrl}/org`, opts?.redirectBackToUrl)
            }
        },
        [props.authUrl]
    )
    const getOrgSettingsPageUrl = useCallback(
        (orgId?: string, opts?: RedirectOptions) => {
            if (orgId) {
                return addReturnToPath(`${props.authUrl}/org/settings/${orgId}`, opts?.redirectBackToUrl)
            } else {
                return addReturnToPath(`${props.authUrl}/org/settings`, opts?.redirectBackToUrl)
            }
        },
        [props.authUrl]
    )
    const getCreateOrgPageUrl = useCallback(
        (opts?: RedirectOptions) => {
            return addReturnToPath(`${props.authUrl}/create_org`, opts?.redirectBackToUrl)
        },
        [props.authUrl]
    )

    const getSetupSAMLPageUrl = useCallback(
        (orgId: string, opts?: RedirectOptions) => {
            return addReturnToPath(`${props.authUrl}/saml?id=${orgId}`, opts?.redirectBackToUrl)
        },
        [props.authUrl]
    )

    const getOrgApiKeysPageUrl = useCallback(
        (orgId?: string, opts?: RedirectOptions) => {
            if (orgId) {
                return addReturnToPath(`${props.authUrl}/org/api_keys/${orgId}`, opts?.redirectBackToUrl)
            } else {
                return addReturnToPath(`${props.authUrl}/org/api_keys`, opts?.redirectBackToUrl)
            }
        },
        [props.authUrl]
    )

    const redirectTo = (url: string) => {
        window.location.href = url
    }

    const redirectToLoginPage = (opts?: RedirectToLoginOptions) => redirectTo(getLoginPageUrl(opts))
    const redirectToSignupPage = (opts?: RedirectToSignupOptions) => redirectTo(getSignupPageUrl(opts))
    const redirectToAccountPage = (opts?: RedirectOptions) => redirectTo(getAccountPageUrl(opts))
    const redirectToOrgPage = (orgId?: string, opts?: RedirectOptions) => redirectTo(getOrgPageUrl(orgId, opts))
    const redirectToOrgSettingsPage = (orgId?: string, opts?: RedirectOptions) =>
        redirectTo(getOrgSettingsPageUrl(orgId, opts))
    const redirectToCreateOrgPage = (opts?: RedirectOptions) => redirectTo(getCreateOrgPageUrl(opts))
    const redirectToSetupSAMLPage = (orgId: string, opts?: RedirectOptions) =>
        redirectTo(getSetupSAMLPageUrl(orgId, opts))
    const redirectToOrgApiKeysPage = (orgId?: string, opts?: RedirectOptions) =>
        redirectTo(getOrgApiKeysPageUrl(orgId, opts))

    const setActiveOrg = useCallback(
        async (orgId: string) => {
            const action = await apiPostSetActiveOrg(orgId)
            if (action.error === 'not_in_org') {
                return undefined
            } else {
                dispatch(action)
                return action.user
            }
        },
        [dispatch]
    )

    const refreshAuthInfo = useCallback(async () => {
        const action = await apiGetUserInfo()
        if (action.error) {
            throw new Error('Failed to refresh token')
        } else {
            dispatch(action)
            return action.user
        }
    }, [dispatch])

    const value = {
        loading: authState.loading,
        userAndAccessToken: authState.userAndAccessToken,
        authUrl: props.authUrl,
        logout,
        redirectToLoginPage,
        redirectToSignupPage,
        redirectToAccountPage,
        redirectToOrgPage,
        redirectToOrgSettingsPage,
        redirectToCreateOrgPage,
        redirectToSetupSAMLPage,
        redirectToOrgApiKeysPage,
        getLoginPageUrl,
        getSignupPageUrl,
        getAccountPageUrl,
        getOrgPageUrl,
        getOrgSettingsPageUrl,
        getCreateOrgPageUrl,
        getOrgApiKeysPageUrl,
        getSetupSAMLPageUrl,
        refreshAuthInfo,
        setActiveOrg,
    }
    return <AuthContext.Provider value={value}>{props.children}</AuthContext.Provider>
}

type UserInfoResponse =
    | {
          error: undefined
          user: User
          accessToken: string
      }
    | {
          error: undefined
          user: undefined
          accessToken: undefined
      }
    | {
          error: 'unexpected'
      }

async function apiGetUserInfo(): Promise<UserInfoResponse> {
    try {
        const userInfoResponse = await fetch('/api/auth/userinfo', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        })

        if (userInfoResponse.ok) {
            const { userinfo, accessToken, impersonatorUserId, activeOrgId } = await userInfoResponse.json()
            const user = new User({
                userId: userinfo.user_id,
                email: userinfo.email,
                emailConfirmed: userinfo.email_confirmed,
                hasPassword: userinfo.has_password,
                username: userinfo.username,
                firstName: userinfo.first_name,
                lastName: userinfo.last_name,
                pictureUrl: userinfo.picture_url,
                orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(userinfo.org_id_to_org_info),
                activeOrgId,
                mfaEnabled: userinfo.mfa_enabled,
                canCreateOrgs: userinfo.can_create_orgs,
                updatePasswordRequired: userinfo.update_password_required,
                createdAt: userinfo.created_at,
                lastActiveAt: userinfo.last_active_at,
                properties: userinfo.properties,
                impersonatorUserId,
            })

            return { user, accessToken, error: undefined }
        } else if (userInfoResponse.status === 401) {
            return { user: undefined, accessToken: undefined, error: undefined }
        } else {
            console.info('Failed to refresh token', userInfoResponse)
            return { error: 'unexpected' }
        }
    } catch (e) {
        console.info('Failed to refresh token', e)
        return { error: 'unexpected' }
    }
}

type SetActiveOrgResponse =
    | {
          user: User
          accessToken: string
          error: undefined
      }
    | {
          error: 'not_in_org'
      }

async function apiPostSetActiveOrg(orgId: string): Promise<SetActiveOrgResponse> {
    try {
        const queryParams = new URLSearchParams({ active_org_id: orgId }).toString()
        const url = `/api/auth/set-active-org?${queryParams}`
        const userInfoResponse = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        })

        if (userInfoResponse.ok) {
            const { userinfo, accessToken, impersonatorUserId, activeOrgId } = await userInfoResponse.json()
            const user = new User({
                userId: userinfo.user_id,
                email: userinfo.email,
                emailConfirmed: userinfo.email_confirmed,
                hasPassword: userinfo.has_password,
                username: userinfo.username,
                firstName: userinfo.first_name,
                lastName: userinfo.last_name,
                pictureUrl: userinfo.picture_url,
                orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(userinfo.org_id_to_org_info),
                activeOrgId,
                mfaEnabled: userinfo.mfa_enabled,
                canCreateOrgs: userinfo.can_create_orgs,
                updatePasswordRequired: userinfo.update_password_required,
                createdAt: userinfo.created_at,
                lastActiveAt: userinfo.last_active_at,
                properties: userinfo.properties,
                impersonatorUserId,
            })

            return { user, accessToken, error: undefined }
        } else if (userInfoResponse.status === 401) {
            return { error: 'not_in_org' }
        } else {
            console.info('Failed to set active org', userInfoResponse)
        }
    } catch (e) {
        console.info('Failed to set active org', e)
    }
    throw new Error('Failed to set active org')
}

const encodeBase64 = (str: string) => {
    const encode = window ? window.btoa : btoa
    return encode(str)
}

const addReturnToPath = (url: string, returnToPath?: string) => {
    if (!returnToPath) {
        return url
    }

    let qs = new URLSearchParams()
    qs.set('rt', encodeBase64(returnToPath))
    if (url.includes('?')) {
        return `${url}&${qs.toString()}`
    } else {
        return `${url}?${qs.toString()}`
    }
}
