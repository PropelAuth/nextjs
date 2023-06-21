import * as jose from "jose"
import {cookies, headers} from "next/headers"
import {redirect} from "next/navigation"
import {ConfigurationException, UnauthorizedException} from "./exceptions"
import {InternalUser, OrgMemberInfo, toOrgIdToOrgMemberInfo, toUser, User} from "../user"
import {NextRequest, NextResponse} from "next/server";
import {ResponseCookie} from "next/dist/compiled/@edge-runtime/cookies";

type RefreshAndAccessTokens = {
    refreshToken: string
    accessToken: string
    error: "none"
}

type RefreshAndAccessTokensUnauthorizedError = {
    error: "unauthorized"
}

type RefreshAndAccessTokensUnexpectedError = {
    error: "unexpected"
}

type RefreshTokenResponse = RefreshAndAccessTokens | RefreshAndAccessTokensUnauthorizedError | RefreshAndAccessTokensUnexpectedError

export const LOGIN_PATH = "/api/auth/login"
export const CALLBACK_PATH = "/api/auth/callback"
export const USERINFO_PATH= "/api/auth/userinfo"
export const LOGOUT_PATH = "/api/auth/logout"
export const ACCESS_TOKEN_COOKIE_NAME = "__pa_at"
export const REFRESH_TOKEN_COOKIE_NAME = "__pa_rt"
export const STATE_COOKIE_NAME = "__pa_state"
export const CUSTOM_HEADER_FOR_ACCESS_TOKEN = "x-propelauth-access-token"

const COOKIE_OPTIONS: Partial<ResponseCookie> = {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
}

export type ServerActionArgs = {
    authUrlOrigin: string
    redirectUri: string
    integrationApiKey: string
    verifierKey: string
    postLoginPathFn: (user: User) => string
}


export type ServerActions = {
    getUser: () => Promise<User | undefined>
    getUserOrRedirect: () => Promise<User>
    validateAccessToken: (accessToken: string) => Promise<User>
    validateAccessTokenOrUndefined: (accessToken: string) => Promise<User | undefined>
    getRouteHandler: (req: NextRequest, { params }: { params: { slug: string } }) => Response | Promise<Response>
    postRouteHandler: (req: NextRequest, { params }: { params: { slug: string } }) => Response | Promise<Response>
    authMiddleware: (req: NextRequest) => Promise<Response>
}

export function getServerActions({
    authUrlOrigin,
    postLoginPathFn,
    verifierKey,
    integrationApiKey,
    redirectUri,
}: ServerActionArgs): ServerActions {
    const publicKeyPromise = jose.importSPKI(verifierKey, "RS256")
    async function getUserOrRedirect(): Promise<User> {
        const user = await getUser()
        if (user) {
            return user
        } else {
            redirect(LOGIN_PATH)
            throw new Error("Redirecting to login")
        }
    }

    async function getUser(): Promise<User | undefined> {
        const accessToken = headers().get(CUSTOM_HEADER_FOR_ACCESS_TOKEN) || cookies().get(ACCESS_TOKEN_COOKIE_NAME)?.value
        if (accessToken) {
            const user = await validateAccessTokenOrUndefined(accessToken)
            if (user) {
                return user
            }
        }
        return undefined
    }

    // Purpose of this middleware is just to keep the access token cookie alive
    // In an ideal world, this could be done in `getUser`, however, you can't
    //   set a cookie in a server component.
    // There also doesn't seem to be any way right now to set a cookie in a
    //   middleware and pass it forward (you can only set them on the response).
    // You CAN, however, pass in custom headers,
    //   so we'll use CUSTOM_HEADER_FOR_ACCESS_TOKEN as a workaround
    async function authMiddleware(req: NextRequest): Promise<Response> {
        if (req.headers.has(CUSTOM_HEADER_FOR_ACCESS_TOKEN)) {
            throw new Error(`${CUSTOM_HEADER_FOR_ACCESS_TOKEN} is set which is for internal use only`)
        } else if (req.nextUrl.pathname === CALLBACK_PATH || req.nextUrl.pathname === LOGOUT_PATH) {
            // Don't do anything for the callback or logout paths, as they will modify the cookies themselves
            return NextResponse.next()
        }

        const accessToken = req.cookies.get(ACCESS_TOKEN_COOKIE_NAME)?.value
        const refreshToken = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value

        // For the userinfo endpoint, we want to get the most up-to-date info, so we'll refresh the access token
        if (req.nextUrl.pathname === USERINFO_PATH && refreshToken) {
            const response = await refreshTokenWithAccessAndRefreshToken(refreshToken)
            if (response.error === "unexpected") {
                throw new Error("Unexpected error while refreshing access token")
            } else if (response.error === "unauthorized") {
                const headers = new Headers()
                headers.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
                headers.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
                return new Response("Unauthorized", {status: 401, headers})
            } else {
                const headers = new Headers(req.headers)
                // Pass along the new access token in a header since cookies don't work
                headers.append(CUSTOM_HEADER_FOR_ACCESS_TOKEN, response.accessToken)
                const nextResponse = NextResponse.next({
                    request: {
                        headers
                    }
                })
                nextResponse.cookies.set(ACCESS_TOKEN_COOKIE_NAME, response.accessToken, COOKIE_OPTIONS)
                nextResponse.cookies.set(REFRESH_TOKEN_COOKIE_NAME, response.refreshToken, COOKIE_OPTIONS)
                return nextResponse
            }
        }

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
            if (response.error === "unexpected") {
                throw new Error("Unexpected error while refreshing access token")
            } else if (response.error === "unauthorized") {
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
                        headers
                    }
                })
                nextResponse.cookies.set(ACCESS_TOKEN_COOKIE_NAME, response.accessToken, COOKIE_OPTIONS)
                nextResponse.cookies.set(REFRESH_TOKEN_COOKIE_NAME, response.refreshToken, COOKIE_OPTIONS)
                return nextResponse
            }
        }

        return NextResponse.next()
    }

    function getRouteHandler(req: NextRequest, { params }: { params: { slug: string } }) {
        if (params.slug === "login") {
            return loginGetHandler()
        } else if (params.slug === "signup") {
            return signupGetHandler()
        } else if (params.slug === "callback") {
            return callbackGetHandler(req)
        } else if (params.slug === "userinfo") {
            return userinfoGetHandler(req)
        } else {
            return new Response("", { status: 404 })
        }
    }

    function postRouteHandler(req: NextRequest, { params }: { params: { slug: string } }) {
        if (params.slug === "logout") {
            return logoutPostHandler(req)
        } else {
            return new Response("", { status: 404 })
        }
    }

    function loginGetHandler() {
        const state = randomState()
        const authorize_url =
            authUrlOrigin + "/propelauth/ssr/authorize?redirect_uri=" + redirectUri + "&state=" + state
        return new Response(null, {
            status: 302,
            headers: {
                Location: authorize_url,
                "Set-Cookie": `${STATE_COOKIE_NAME}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`,
            }
        })
    }

    function signupGetHandler() {
        const state = randomState()
        const authorize_url =
            authUrlOrigin + "/propelauth/ssr/authorize?redirect_uri=" + redirectUri + "&state=" + state + "&signup=true"
        return new Response(null, {
            status: 302,
            headers: {
                Location: authorize_url,
                "Set-Cookie": `${STATE_COOKIE_NAME}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`,
            }
        })
    }

    async function callbackGetHandler(req: NextRequest) {
        const oauthState = req.cookies.get(STATE_COOKIE_NAME)?.value
        if (!oauthState || oauthState.length !== 64) {
            console.log("No oauth state found")
            return new Response(null, { status: 302, headers: { Location: LOGIN_PATH } })
        }

        const queryParams = req.nextUrl.searchParams
        const state = queryParams.get("state")
        const code = queryParams.get("code")
        if (state !== oauthState) {
            console.log("Mismatch between states, redirecting to login")
            return new Response(null, { status: 302, headers: { Location: LOGIN_PATH } })
        }

        const oauth_token_body = {
            redirect_uri: redirectUri,
            code,
        }
        const url = `${authUrlOrigin}/propelauth/ssr/token`
        const response = await fetch(url, {
            method: "POST",
            body: JSON.stringify(oauth_token_body),
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + integrationApiKey,
            },
        })

        if (response.ok) {
            const data = await response.json()

            const accessToken = data.access_token
            const user = await validateAccessToken(accessToken)
            const path = postLoginPathFn(user)
            if (!path) {
                console.log("postLoginPathFn returned undefined")
                return new Response("Unexpected error", { status: 500 })
            }

            const headers = new Headers()
            headers.append("Location", path)
            headers.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`)
            headers.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=${data.refresh_token}; Path=/; HttpOnly; Secure; SameSite=Lax`)
            return new Response(null, {
                status: 302,
                headers
            })
        } else if (response.status === 401) {
            return new Response("Unexpected error", { status: 500 })
        } else {
            return new Response("Unexpected error", { status: 500 })
        }
    }

    async function userinfoGetHandler(req: NextRequest) {
        const accessToken = req.headers.get(CUSTOM_HEADER_FOR_ACCESS_TOKEN) || req.cookies.get(ACCESS_TOKEN_COOKIE_NAME)?.value
        if (accessToken) {
            const path = `${authUrlOrigin}/propelauth/oauth/userinfo`
            const response = await fetch(path, {
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + accessToken,
                }
            })
            if (response.ok) {
                const data = await response.json()

                const user = new User(
                    data.user_id,
                    data.email,
                    toOrgIdToOrgMemberInfo(data.org_id_to_org_info),
                    data.first_name,
                    data.last_name,
                    data.username,
                    data.legacy_user_id,
                    data.impersonator_user_id,
                )

                return new Response(JSON.stringify(user), {
                    status: 200,
                    headers: {
                        "Content-Type": "application/json",
                    }
                })
            } else if (response.status === 401) {
                return new Response(null, { status: 401 })
            } else {
                return new Response(null, { status: 500 })
            }
        }
        return new Response(null, { status: 401 })
    }

    async function refreshTokenWithAccessAndRefreshToken(refreshToken: string): Promise<RefreshTokenResponse> {
        const body = {
            refresh_token: refreshToken,
        }
        const url = `${authUrlOrigin}/api/backend/v1/refresh_token`
        const response = await fetch(url, {
            method: "POST",
            body: JSON.stringify(body),
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + integrationApiKey,
            },
        })

        if (response.ok) {
            const data = await response.json()
            const newRefreshToken = data.refresh_token
            const {
                access_token: accessToken,
                expires_at_seconds: expiresAtSeconds,
            } = data.access_token

            return {
                refreshToken: newRefreshToken,
                accessToken,
                error: "none",
            }
        } else if (response.status === 400) {
            return { error: "unauthorized" }
        } else {
            return { error: "unexpected" }
        }
    }

    async function logoutPostHandler(req: NextRequest) {
        const refresh_token = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value
        if (!refresh_token) {
            const headers = new Headers()
            headers.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
            headers.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
            return new Response(null, { status: 200, headers })
        }

        const logoutBody = { refresh_token }
        const url = `${authUrlOrigin}/api/backend/v1/logout`
        const response = await fetch(url, {
            method: "POST",
            body: JSON.stringify(logoutBody),
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + integrationApiKey,
            },
        })

        if (!response.ok) {
            console.log(
                "Unable to logout, clearing cookies and continuing anyway",
                response.status,
                response.statusText
            )
        }
        const headers = new Headers()
        headers.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        headers.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
        return new Response(null, { status: 200, headers })
    }

    async function validateAccessTokenOrUndefined(accessToken: string | undefined): Promise<User | undefined> {
        try {
            return await validateAccessToken(accessToken)
        } catch (err) {
            if (err instanceof ConfigurationException) {
                throw err
            } else if (err instanceof UnauthorizedException) {
                return undefined
            } else {
                console.log("Error validating access token", err)
                return undefined
            }
        }
    }

    async function validateAccessToken(accessToken: string | undefined): Promise<User> {
        let publicKey
        try {
            publicKey = await publicKeyPromise
        } catch (err) {
            console.error("Verifier key is invalid. Make sure it's specified correctly, including the newlines.", err)
            throw new ConfigurationException("Invalid verifier key")
        }

        if (!accessToken) {
            throw new UnauthorizedException("No access token provided")
        }

        let accessTokenWithoutBearer = accessToken
        if (accessToken.toLowerCase().startsWith("bearer ")) {
            accessTokenWithoutBearer = accessToken.substring("bearer ".length)
        }

        try {
            const { payload } = await jose.jwtVerify(accessTokenWithoutBearer, publicKey, {
                issuer: authUrlOrigin,
                algorithms: ["RS256"],
            })

            return toUser(<InternalUser>payload)
        } catch (e) {
            if (e instanceof Error) {
                throw new UnauthorizedException(e.message)
            } else {
                throw new UnauthorizedException("Unable to decode jwt")
            }
        }
    }

    return {
        getUser,
        getUserOrRedirect,
        validateAccessToken,
        validateAccessTokenOrUndefined,
        getRouteHandler,
        postRouteHandler,
        authMiddleware,
    }
}

function randomState(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32))
    return Array.from(randomBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
}