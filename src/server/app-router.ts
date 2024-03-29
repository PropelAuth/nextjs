import { redirect } from 'next/navigation.js'
import { cookies, headers } from 'next/headers.js'
import { NextRequest, NextResponse } from 'next/server.js'
import {
    ACCESS_TOKEN_COOKIE_NAME,
    CALLBACK_PATH,
    COOKIE_OPTIONS,
    CUSTOM_HEADER_FOR_ACCESS_TOKEN,
    getAuthUrlOrigin,
    getIntegrationApiKey,
    getRedirectUri,
    LOGIN_PATH,
    LOGOUT_PATH,
    REFRESH_TOKEN_COOKIE_NAME,
    refreshTokenWithAccessAndRefreshToken,
    RETURN_TO_PATH_COOKIE_NAME,
    STATE_COOKIE_NAME,
    USERINFO_PATH,
    validateAccessToken,
    validateAccessTokenOrUndefined,
} from './shared'
import { UserFromToken } from './index'

export async function getUserOrRedirect(): Promise<UserFromToken> {
    const user = await getUser()
    if (user) {
        return user
    } else {
        redirect(LOGIN_PATH)
        throw new Error('Redirecting to login')
    }
}

export async function getUser(): Promise<UserFromToken | undefined> {
    const accessToken = headers().get(CUSTOM_HEADER_FOR_ACCESS_TOKEN) || cookies().get(ACCESS_TOKEN_COOKIE_NAME)?.value
    if (accessToken) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return user
        }
    }
    return undefined
}

export async function getAccessToken(): Promise<string | undefined> {
    return headers().get(CUSTOM_HEADER_FOR_ACCESS_TOKEN) || cookies().get(ACCESS_TOKEN_COOKIE_NAME)?.value
}

// Purpose of this middleware is just to keep the access token cookie alive
// In an ideal world, this could be done in `getUser`, however, you can't
//   set a cookie in a server component.
// There also doesn't seem to be any way right now to set a cookie in a
//   middleware and pass it forward (you can only set them on the response).
// You CAN, however, pass in custom headers,
//   so we'll use CUSTOM_HEADER_FOR_ACCESS_TOKEN as a workaround
export async function authMiddleware(req: NextRequest): Promise<Response> {
    if (req.headers.has(CUSTOM_HEADER_FOR_ACCESS_TOKEN)) {
        throw new Error(`${CUSTOM_HEADER_FOR_ACCESS_TOKEN} is set which is for internal use only`)
    } else if (
        req.nextUrl.pathname === CALLBACK_PATH ||
        req.nextUrl.pathname === LOGOUT_PATH ||
        req.nextUrl.pathname === USERINFO_PATH
    ) {
        // Don't do anything for the callback, logout, or userinfo paths, as they will modify the cookies themselves
        return NextResponse.next()
    }

    const accessToken = req.cookies.get(ACCESS_TOKEN_COOKIE_NAME)?.value
    const refreshToken = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value

    // If we are authenticated, we can continue
    if (accessToken) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return NextResponse.next()
        }
    }

    // Otherwise, we need to refresh the access token
    if (refreshToken) {
        const response = await refreshTokenWithAccessAndRefreshToken(refreshToken)
        if (response.error === 'unexpected') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (response.error === 'unauthorized') {
            const response = NextResponse.next()
            response.cookies.delete(ACCESS_TOKEN_COOKIE_NAME)
            response.cookies.delete(REFRESH_TOKEN_COOKIE_NAME)
            return response
        } else {
            const headers = new Headers(req.headers)
            // Pass along the new access token in a header since cookies don't work
            headers.append(CUSTOM_HEADER_FOR_ACCESS_TOKEN, response.accessToken)
            const nextResponse = NextResponse.next({
                request: {
                    headers,
                },
            })
            nextResponse.cookies.set(ACCESS_TOKEN_COOKIE_NAME, response.accessToken, COOKIE_OPTIONS)
            nextResponse.cookies.set(REFRESH_TOKEN_COOKIE_NAME, response.refreshToken, COOKIE_OPTIONS)
            return nextResponse
        }
    }

    return NextResponse.next()
}

export type RouteHandlerArgs = {
    postLoginRedirectPathFn?: (req: NextRequest) => string
}

export function getRouteHandlers(args?: RouteHandlerArgs) {
    function loginGetHandler(req: NextRequest) {
        return signupOrLoginHandler(req, false)
    }

    function signupGetHandler(req: NextRequest) {
        return signupOrLoginHandler(req, true)
    }

    function signupOrLoginHandler(req: NextRequest, isSignup: boolean) {
        const returnToPath = req.nextUrl.searchParams.get('return_to_path')
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

        return new Response(null, {
            status: 302,
            headers,
        })
    }

    async function callbackGetHandler(req: NextRequest) {
        const oauthState = req.cookies.get(STATE_COOKIE_NAME)?.value
        if (!oauthState || oauthState.length !== 64) {
            return new Response(null, { status: 302, headers: { Location: LOGIN_PATH } })
        }

        const queryParams = req.nextUrl.searchParams
        const state = queryParams.get('state')
        const code = queryParams.get('code')
        if (state !== oauthState) {
            return new Response(null, { status: 302, headers: { Location: LOGIN_PATH } })
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
            const returnToPathFromCookie = req.cookies.get(RETURN_TO_PATH_COOKIE_NAME)?.value
            const returnToPath =
                returnToPathFromCookie ?? (args?.postLoginRedirectPathFn ? args.postLoginRedirectPathFn(req) : '/')
            if (!returnToPath) {
                console.error('postLoginRedirectPathFn returned undefined')
                return new Response('Unexpected error', { status: 500 })
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
            headers.append(
                'Set-Cookie',
                `${RETURN_TO_PATH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            return new Response(null, {
                status: 302,
                headers,
            })
        } else if (response.status === 401) {
            console.error(
                "Couldn't finish the login process for this user. This is most likely caused by an incorrect PROPELAUTH_API_KEY."
            )
            return new Response('Unexpected error', { status: 500 })
        } else {
            return new Response('Unexpected error', { status: 500 })
        }
    }

    async function userinfoGetHandler(req: NextRequest) {
        const oldRefreshToken = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value

        // For the userinfo endpoint, we want to get the most up-to-date info, so we'll refresh the access token
        if (oldRefreshToken) {
            const refreshResponse = await refreshTokenWithAccessAndRefreshToken(oldRefreshToken)
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
                return new Response('Unauthorized', { status: 401, headers })
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
                return new Response(JSON.stringify(jsonResponse), {
                    status: 200,
                    headers,
                })
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
                return new Response(null, {
                    status: 401,
                    headers,
                })
            } else {
                return new Response(null, { status: 500 })
            }
        }

        const headers = new Headers()
        headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return new Response(null, { status: 401 })
    }

    async function logoutGetHandler(req: NextRequest) {
        // Real logout requests will go to the logout POST handler
        // This endpoint is a landing page for when people logout from the hosted UIs
        // Instead of doing a logout we'll check the refresh token.
        // If it's invalid, we'll clear the cookies and redirect using the postLoginRedirectPathFn
        const path = args?.postLoginRedirectPathFn ? args.postLoginRedirectPathFn(req) : '/'
        if (!path) {
            console.error('postLoginPathFn returned undefined')
            return new Response('Unexpected error', { status: 500 })
        }

        const refreshToken = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value
        if (!refreshToken) {
            const headers = new Headers()
            headers.append('Location', path)
            headers.append(
                'Set-Cookie',
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            return new Response(null, {
                status: 302,
                headers,
            })
        }

        const refreshResponse = await refreshTokenWithAccessAndRefreshToken(refreshToken)
        if (refreshResponse.error === 'unexpected') {
            console.error('Unexpected error while refreshing access token')
            return new Response('Unexpected error', { status: 500 })
        } else if (refreshResponse.error === 'unauthorized') {
            const headers = new Headers()
            headers.append('Location', path)
            headers.append(
                'Set-Cookie',
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            return new Response(null, {
                status: 302,
                headers,
            })
        } else {
            const headers = new Headers()
            headers.append('Location', path)
            return new Response(null, {
                status: 302,
                headers,
            })
        }
    }

    async function logoutPostHandler(req: NextRequest) {
        const refreshToken = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value
        if (!refreshToken) {
            const headers = new Headers()
            headers.append(
                'Set-Cookie',
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            headers.append(
                'Set-Cookie',
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            )
            return new Response(null, { status: 200, headers })
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
            console.warn(
                'Unable to logout, clearing cookies and continuing anyway',
                response.status,
                response.statusText
            )
        }
        const headers = new Headers()
        headers.append('Set-Cookie', `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append('Set-Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return new Response(null, { status: 200, headers })
    }

    function getRouteHandler(req: NextRequest, { params }: { params: { slug: string } }) {
        if (params.slug === 'login') {
            return loginGetHandler(req)
        } else if (params.slug === 'signup') {
            return signupGetHandler(req)
        } else if (params.slug === 'callback') {
            return callbackGetHandler(req)
        } else if (params.slug === 'userinfo') {
            return userinfoGetHandler(req)
        } else if (params.slug === 'logout') {
            return logoutGetHandler(req)
        } else {
            return new Response('', { status: 404 })
        }
    }

    function postRouteHandler(req: NextRequest, { params }: { params: { slug: string } }) {
        if (params.slug === 'logout') {
            return logoutPostHandler(req)
        } else {
            return new Response('', { status: 404 })
        }
    }

    return {
        getRouteHandler,
        postRouteHandler,
    }
}

function randomState(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32))
    return Array.from(randomBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}
