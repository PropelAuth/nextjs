import {
    ACCESS_TOKEN_COOKIE_NAME,
    getAuthUrlOrigin,
    getIntegrationApiKey,
    getRedirectUri,
    LOGIN_PATH,
    REFRESH_TOKEN_COOKIE_NAME,
    refreshTokenWithAccessAndRefreshToken,
    RETURN_TO_PATH_COOKIE_NAME,
    STATE_COOKIE_NAME,
    validateAccessToken,
} from './shared'
import { ACTIVE_ORG_ID_COOKIE_NAME } from '../shared'
import { UserFromToken } from '../user'

export type GenericResponse =
    | {
          status: number
          headers: Headers
          responseType: 'none'
      }
    | {
          status: number
          headers: Headers
          responseType: 'json'
          body: object
      }
    | {
          status: number
          headers: Headers
          responseType: 'text'
          body: string
      }

export type GenericSignupOrLoginHandlerArgs = {
    returnToPath: string | undefined
}

export function genericLoginGetHandler(args: GenericSignupOrLoginHandlerArgs): GenericResponse {
    return signupOrLoginHandler(args, false)
}

export function genericSignupGetHandler(args: GenericSignupOrLoginHandlerArgs): GenericResponse {
    return signupOrLoginHandler(args, true)
}

function signupOrLoginHandler(args: GenericSignupOrLoginHandlerArgs, isSignup: boolean): GenericResponse {
    const returnToPath = args.returnToPath
    const state = randomState()
    const redirectUri = getRedirectUri()

    const authorizeUrlSearchParams = new URLSearchParams({
        redirect_uri: redirectUri,
        state,
        signup: isSignup ? 'true' : 'false',
    })
    const authorize_url = getAuthUrlOrigin() + '/propelauth/ssr/authorize?' + authorizeUrlSearchParams.toString()

    const headers = new Headers()
    headers.append('Location', authorize_url)
    headers.append('Set-Cookie', `${STATE_COOKIE_NAME}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`)
    if (returnToPath) {
        if (returnToPath.startsWith('/')) {
            headers.append(
                'Set-Cookie',
                `${RETURN_TO_PATH_COOKIE_NAME}=${returnToPath}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
            )
        } else {
            console.warn('return_to_path must start with /')
        }
    }

    return {
        status: 302,
        headers,
        responseType: 'none',
    }
}

export type GenericCallbackGetHandlerArgs = {
    returnToPathFromCookie: string | undefined
    activeOrgIdFromCookie: string | undefined
    stateFromCookie: string | undefined
    stateFromQuery: string | undefined
    codeFromQuery: string | undefined
    postLoginRedirectPathFn?: () => string
    getDefaultActiveOrgId?: (user: UserFromToken) => string | undefined
}

export async function genericCallbackGetHandler(args: GenericCallbackGetHandlerArgs): Promise<GenericResponse> {
    const oauthState = args.stateFromCookie
    if (!oauthState || oauthState.length !== 64) {
        return {
            status: 302,
            headers: new Headers({ Location: LOGIN_PATH }),
            responseType: 'none',
        }
    }

    const state = args.stateFromQuery
    const code = args.codeFromQuery
    if (state !== oauthState) {
        return {
            status: 302,
            headers: new Headers({ Location: LOGIN_PATH }),
            responseType: 'none',
        }
    }

    const authUrlOrigin = getAuthUrlOrigin()
    const redirectUri = getRedirectUri()
    const integrationApiKey = getIntegrationApiKey()
    const oauth_token_body = {
        redirect_uri: redirectUri,
        code,
    }
    const url = `${authUrlOrigin}/propelauth/ssr/token`
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify(oauth_token_body),
        headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer ' + integrationApiKey,
        },
    })

    if (response.ok) {
        const data = await response.json()

        const accessToken = data.access_token

        // If we have a return_to_path cookie, we'll use that
        // Otherwise, we'll use the postLoginRedirectPathFn
        const returnToPathFromCookie = args.returnToPathFromCookie
        const returnToPath =
            returnToPathFromCookie ?? (args?.postLoginRedirectPathFn ? args.postLoginRedirectPathFn() : '/')
        if (!returnToPath) {
            console.error('postLoginRedirectPathFn returned undefined')
            return {
                status: 500,
                headers: new Headers(),
                responseType: 'text',
                body: 'Unexpected error',
            }
        }

        // For Active Org, if there is one set, we need to issue a new access token
        // We start by checking if there's an existing cookie AND the user is in that org
        // Otherwise, we'll use the default active org function to get the active org
        // If none of that, we'll just use the access token as is
        const currentActiveOrgId = args.activeOrgIdFromCookie

        const user = await validateAccessToken(accessToken)
        const isUserInCurrentActiveOrg = !!currentActiveOrgId && !!user.getOrg(currentActiveOrgId)

        let activeOrgId = undefined
        if (isUserInCurrentActiveOrg) {
            activeOrgId = currentActiveOrgId
        } else if (args?.getDefaultActiveOrgId) {
            activeOrgId = args.getDefaultActiveOrgId(user)
        }

        // If there's an active org, we need to re-issue a new access token for the active org
        if (activeOrgId) {
            const response = await refreshTokenWithAccessAndRefreshToken(data.refresh_token, activeOrgId)
            if (response.error === 'unexpected') {
                throw new Error('Unexpected error while setting active org')
            } else if (response.error === 'unauthorized') {
                console.error('Unauthorized error while setting active org. Your user may not have access to this org')
                return {
                    status: 401,
                    headers: new Headers(),
                    responseType: 'text',
                    body: 'Unauthorized',
                }
            } else {
                const headers = new Headers()
                headers.append('Location', returnToPath)
                headers.append(
                    'Set-Cookie',
                    `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
                )
                headers.append(
                    'Set-Cookie',
                    `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
                )
                headers.append(
                    'Set-Cookie',
                    `${ACTIVE_ORG_ID_COOKIE_NAME}=${activeOrgId}; Path=/; HttpOnly; Secure; SameSite=Lax`
                )
                headers.append(
                    'Set-Cookie',
                    `${RETURN_TO_PATH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
                )
                return {
                    status: 302,
                    headers,
                    responseType: 'none',
                }
            }
        }

        const headers = new Headers()
        headers.append('Location', returnToPath)
        headers.append(
            'Set-Cookie',
            `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        )
        headers.append(
            'Set-Cookie',
            `${REFRESH_TOKEN_COOKIE_NAME}=${data.refresh_token}; Path=/; HttpOnly; Secure; SameSite=Lax`
        )
        headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append(
            'Set-Cookie',
            `${RETURN_TO_PATH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        )
        return {
            status: 302,
            headers,
            responseType: 'none',
        }
    } else if (response.status === 401) {
        console.error(
            "Couldn't finish the login process for this user. This is most likely caused by an incorrect PROPELAUTH_API_KEY."
        )
        return {
            status: 500,
            headers: new Headers(),
            responseType: 'text',
            body: 'Unexpected error',
        }
    } else {
        return {
            status: 500,
            headers: new Headers(),
            responseType: 'text',
            body: 'Unexpected error',
        }
    }
}

export type GenericUserInfoGetHandlerArgs = {
    refreshToken: string | undefined
    activeOrgId: string | undefined
}

export async function genericUserinfoGetHandler(args: GenericUserInfoGetHandlerArgs): Promise<GenericResponse> {
    const oldRefreshToken = args.refreshToken
    const activeOrgId = args.activeOrgId

    // For the userinfo endpoint, we want to get the most up-to-date info, so we'll refresh the access token
    if (oldRefreshToken) {
        const refreshResponse = await refreshTokenWithAccessAndRefreshToken(oldRefreshToken, activeOrgId)
        if (refreshResponse.error === 'unexpected') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (refreshResponse.error === 'unauthorized') {
            const headers = new Headers()
            headers.append(
                'Set-Cookie',
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            return {
                status: 401,
                headers,
                responseType: 'text',
                body: 'Unauthorized',
            }
        }

        const refreshToken = refreshResponse.refreshToken
        const accessToken = refreshResponse.accessToken

        const authUrlOrigin = getAuthUrlOrigin()
        const path = `${authUrlOrigin}/propelauth/oauth/userinfo`
        const response = await fetch(path, {
            headers: {
                'Content-Type': 'application/json',
                Authorization: 'Bearer ' + accessToken,
            },
        })
        if (response.ok) {
            const userFromToken = await validateAccessToken(accessToken)
            const data = await response.json()
            const jsonResponse = {
                userinfo: data,
                accessToken,
                impersonatorUserId: userFromToken.impersonatorUserId,
                activeOrgId,
            }

            const headers = new Headers()
            headers.append(
                'Set-Cookie',
                `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
            )
            headers.append(
                'Set-Cookie',
                `${REFRESH_TOKEN_COOKIE_NAME}=${refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
            )
            headers.append('Content-Type', 'application/json')
            return {
                status: 200,
                headers,
                responseType: 'json',
                body: jsonResponse,
            }
        } else if (response.status === 401) {
            const headers = new Headers()
            headers.append(
                'Set-Cookie',
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            return {
                status: 401,
                headers,
                responseType: 'none',
            }
        } else {
            return {
                status: 500,
                headers: new Headers(),
                responseType: 'none',
            }
        }
    }

    const headers = new Headers()
    headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
    headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
    headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
    return {
        status: 401,
        headers,
        responseType: 'none',
    }
}

export type GenericLogoutGetHandlerArgs = {
    refreshToken: string | undefined
    activeOrgId: string | undefined
    postLoginRedirectPathFn?: () => string
}

export async function genericLogoutGetHandler(args: GenericLogoutGetHandlerArgs): Promise<GenericResponse> {
    // Real logout requests will go to the logout POST handler
    // This endpoint is a landing page for when people logout from the hosted UIs
    // Instead of doing a logout we'll check the refresh token.
    // If it's invalid, we'll clear the cookies and redirect using the postLoginRedirectPathFn
    const path = args?.postLoginRedirectPathFn ? args.postLoginRedirectPathFn() : '/'
    if (!path) {
        console.error('postLoginPathFn returned undefined')
        return {
            status: 500,
            headers: new Headers(),
            responseType: 'text',
            body: 'Unexpected error',
        }
    }

    const refreshToken = args.refreshToken
    if (!refreshToken) {
        const headers = new Headers()
        headers.append('Location', path)
        headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return {
            status: 302,
            headers,
            responseType: 'none',
        }
    }

    const activeOrgId = args.activeOrgId
    const refreshResponse = await refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId)
    if (refreshResponse.error === 'unexpected') {
        console.error('Unexpected error while refreshing access token')
        return {
            status: 500,
            headers: new Headers(),
            responseType: 'text',
            body: 'Unexpected error',
        }
    } else if (refreshResponse.error === 'unauthorized') {
        const headers = new Headers()
        headers.append('Location', path)
        headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return {
            status: 302,
            headers,
            responseType: 'none',
        }
    } else {
        const headers = new Headers()
        headers.append('Location', path)
        return {
            status: 302,
            headers,
            responseType: 'none',
        }
    }
}

export type GenericLogoutPostHandlerArgs = {
    refreshToken: string | undefined
}

export async function genericLogoutPostHandler(args: GenericLogoutPostHandlerArgs): Promise<GenericResponse> {
    const refreshToken = args.refreshToken
    if (!refreshToken) {
        const headers = new Headers()
        headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return {
            status: 200,
            headers,
            responseType: 'none',
        }
    }

    const authUrlOrigin = getAuthUrlOrigin()
    const integrationApiKey = getIntegrationApiKey()
    const logoutBody = { refresh_token: refreshToken }
    const url = `${authUrlOrigin}/api/backend/v1/logout`
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify(logoutBody),
        headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer ' + integrationApiKey,
        },
    })

    if (!response.ok) {
        console.warn('Unable to logout, clearing cookies and continuing anyway', response.status, response.statusText)
    }
    const headers = new Headers()
    headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
    headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
    headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
    return {
        status: 200,
        headers,
        responseType: 'none',
    }
}

export type GenericSetActiveOrgHandlerArgs = {
    refreshToken: string | undefined
    activeOrgId: string | undefined
}

export async function genericSetActiveOrgHandler(args: GenericSetActiveOrgHandlerArgs): Promise<GenericResponse> {
    const oldRefreshToken = args.refreshToken
    const activeOrgId = args.activeOrgId

    if (!oldRefreshToken) {
        const headers = new Headers()
        headers.append('Set-Cookie', `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return {
            status: 401,
            headers,
            responseType: 'none',
        }
    }

    if (!activeOrgId) {
        return {
            status: 400,
            headers: new Headers(),
            responseType: 'none',
        }
    }

    const refreshResponse = await refreshTokenWithAccessAndRefreshToken(oldRefreshToken, activeOrgId)
    if (refreshResponse.error === 'unexpected') {
        throw new Error('Unexpected error while setting active org id')
    } else if (refreshResponse.error === 'unauthorized') {
        return {
            status: 401,
            headers: new Headers(),
            responseType: 'none',
        }
    }

    const refreshToken = refreshResponse.refreshToken
    const accessToken = refreshResponse.accessToken

    const authUrlOrigin = getAuthUrlOrigin()
    const path = `${authUrlOrigin}/propelauth/oauth/userinfo`
    const response = await fetch(path, {
        headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer ' + accessToken,
        },
    })

    if (response.ok) {
        const userFromToken = await validateAccessToken(accessToken)
        const data = await response.json()
        const jsonResponse = {
            userinfo: data,
            accessToken,
            impersonatorUserId: userFromToken.impersonatorUserId,
            activeOrgId,
        }

        const headers = new Headers()
        headers.append(
            'Set-Cookie',
            `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        )
        headers.append(
            'Set-Cookie',
            `${REFRESH_TOKEN_COOKIE_NAME}=${refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        )
        headers.append(
            'Set-Cookie',
            `${ACTIVE_ORG_ID_COOKIE_NAME}=${activeOrgId}; Path=/; HttpOnly; Secure; SameSite=Lax`
        )
        headers.append('Content-Type', 'application/json')
        return {
            status: 200,
            headers,
            responseType: 'json',
            body: jsonResponse,
        }
    } else if (response.status === 401) {
        return {
            status: 401,
            headers: new Headers(),
            responseType: 'none',
        }
    } else {
        return {
            status: 500,
            headers: new Headers(),
            responseType: 'none',
        }
    }
}

function randomState(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32))
    return Array.from(randomBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}
