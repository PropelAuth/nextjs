'use client'

import React, { useCallback, useEffect, useReducer } from 'react'
import { doesLocalStorageMatch, hasWindow, isEqual, saveUserToLocalStorage, USER_INFO_KEY } from './utils'
import { useRouter } from 'next/navigation.js'
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

export type AuthProviderProps = {
    authUrl: string
    reloadOnAuthChange?: boolean
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
    const router = useRouter()
    const reloadOnAuthChange = props.reloadOnAuthChange ?? true

    const dispatch = useCallback(
        (action: AuthStateAction) => {
            dispatchInner(action)
            saveUserToLocalStorage(action.user)
        },
        [dispatchInner]
    )

    // This is because we don't have a good way to trigger server components to reload outside of router.refresh()
    // Once server actions isn't alpha, we can hopefully use that instead
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
        let retryTimer: NodeJS.Timeout | undefined = undefined

        function clearAndSetRetryTimer() {
            if (retryTimer) {
                clearTimeout(retryTimer)
            }
            retryTimer = setTimeout(refreshToken, 30 * 1000)
        }

        async function refreshToken() {
            const action = await apiGetUserInfo()
            if (didCancel) {
                return
            }
            if (!action.error) {
                dispatch(action)
            } else if (action.error === 'unexpected') {
                clearAndSetRetryTimer()
            }
        }

        async function onStorageEvent(event: StorageEvent) {
            if (
                event.key === USER_INFO_KEY &&
                !doesLocalStorageMatch(event.newValue, authState.userAndAccessToken.user)
            ) {
                await refreshToken()
            }
        }

        const interval = setInterval(refreshToken, 5 * 60 * 1000)

        if (hasWindow()) {
            window.addEventListener('storage', onStorageEvent)
            window.addEventListener('online', refreshToken)

            // Default for refreshOnFocus is true
            if (props.refreshOnFocus !== false) {
                window.addEventListener('focus', refreshToken)
            }
        }

        return () => {
            didCancel = true
            clearInterval(interval)
            if (retryTimer) {
                clearTimeout(retryTimer)
            }
            if (hasWindow()) {
                window.removeEventListener('storage', onStorageEvent)
                window.removeEventListener('online', refreshToken)
                window.removeEventListener('focus', refreshToken)
            }
        }
    }, [dispatch, authState.userAndAccessToken.user])

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

    const getLoginPageUrl = (opts?: RedirectToLoginOptions) => {
        if (opts?.postLoginRedirectPath) {
            return `/api/auth/login?return_to_path=${encodeURIComponent(opts.postLoginRedirectPath)}`
        }

        return '/api/auth/login'
    }
    const getSignupPageUrl = (opts?: RedirectToSignupOptions) => {
        if (opts?.postSignupRedirectPath) {
            return `/api/auth/signup?return_to_path=${encodeURIComponent(opts.postSignupRedirectPath)}`
        }

        return '/api/auth/signup'
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

    const refreshAuthInfo = useCallback(async () => {
        const action = await apiGetUserInfo()
        if (action.error) {
            throw new Error('Failed to refresh token')
        } else {
            dispatch(action)
            return action.user
        }
    }, [dispatch])

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

    const value = {
        loading: authState.loading,
        userAndAccessToken: authState.userAndAccessToken,
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
