import {toOrgIdToOrgMemberInfo, User} from "../user";
import {redirect} from "next/navigation";
import {cookies, headers} from "next/headers";
import {NextRequest, NextResponse} from "next/server";
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
    STATE_COOKIE_NAME,
    USERINFO_PATH,
    validateAccessToken,
    validateAccessTokenOrUndefined
} from "./shared";

export async function getUserOrRedirect(): Promise<User> {
    const user = await getUser()
    if (user) {
        return user
    } else {
        redirect(LOGIN_PATH)
        throw new Error("Redirecting to login")
    }
}

export async function getUser(): Promise<User | undefined> {
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
export async function authMiddleware(req: NextRequest): Promise<Response> {
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

export type RouteHandlerArgs = {
    postLoginRedirectPathFn?: (user: User, req: NextRequest) => string
}

export function getRouteHandlers(args?: RouteHandlerArgs) {
    const authUrlOrigin = getAuthUrlOrigin()
    const redirectUri = getRedirectUri()
    const integrationApiKey = getIntegrationApiKey()

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
            getAuthUrlOrigin() + "/propelauth/ssr/authorize?redirect_uri=" + redirectUri + "&state=" + state + "&signup=true"
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
            return new Response(null, {status: 302, headers: {Location: LOGIN_PATH}})
        }

        const queryParams = req.nextUrl.searchParams
        const state = queryParams.get("state")
        const code = queryParams.get("code")
        if (state !== oauthState) {
            console.log("Mismatch between states, redirecting to login")
            return new Response(null, {status: 302, headers: {Location: LOGIN_PATH}})
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
            const path = args?.postLoginRedirectPathFn ? args.postLoginRedirectPathFn(user, req) : "/"
            if (!path) {
                console.log("postLoginPathFn returned undefined")
                return new Response("Unexpected error", {status: 500})
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
            return new Response("Unexpected error", {status: 500})
        } else {
            return new Response("Unexpected error", {status: 500})
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
                return new Response(null, {status: 401})
            } else {
                return new Response(null, {status: 500})
            }
        }
        return new Response(null, {status: 401})
    }

    async function logoutPostHandler(req: NextRequest) {
        const refresh_token = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value
        if (!refresh_token) {
            const headers = new Headers()
            headers.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
            headers.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`)
            return new Response(null, {status: 200, headers})
        }

        const logoutBody = {refresh_token}
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
        return new Response(null, {status: 200, headers})
    }

    function getRouteHandler(req: NextRequest, {params}: { params: { slug: string } }) {
        if (params.slug === "login") {
            return loginGetHandler()
        } else if (params.slug === "signup") {
            return signupGetHandler()
        } else if (params.slug === "callback") {
            return callbackGetHandler(req)
        } else if (params.slug === "userinfo") {
            return userinfoGetHandler(req)
        } else {
            return new Response("", {status: 404})
        }
    }

    function postRouteHandler(req: NextRequest, {params}: { params: { slug: string } }) {
        if (params.slug === "logout") {
            return logoutPostHandler(req)
        } else {
            return new Response("", {status: 404})
        }
    }

    return {
        getRouteHandler,
        postRouteHandler
    }
}

function randomState(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32))
    return Array.from(randomBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
}

