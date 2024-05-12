import { redirect } from 'next/navigation.js'
import { cookies, headers } from 'next/headers.js'
import { NextRequest, NextResponse } from 'next/server.js'
import {
    ACCESS_TOKEN_COOKIE_NAME,
    assertNever,
    CALLBACK_PATH,
    COOKIE_OPTIONS,
    CUSTOM_HEADER_FOR_ACCESS_TOKEN,
    CUSTOM_HEADER_FOR_PATH,
    CUSTOM_HEADER_FOR_URL,
    LOGIN_PATH,
    LOGOUT_PATH,
    REFRESH_TOKEN_COOKIE_NAME,
    refreshTokenWithAccessAndRefreshToken,
    RETURN_TO_PATH_COOKIE_NAME,
    STATE_COOKIE_NAME,
    USERINFO_PATH,
    validateAccessTokenOrUndefined,
} from './shared'
import { UserFromToken } from './index'
import { ACTIVE_ORG_ID_COOKIE_NAME } from '../shared'
import {
    genericCallbackGetHandler,
    genericLoginGetHandler,
    genericLogoutGetHandler,
    genericLogoutPostHandler,
    GenericResponse,
    genericSetActiveOrgHandler,
    genericSignupGetHandler,
    genericUserinfoGetHandler,
} from './shared-apis'

export type RedirectOptions =
    | {
          returnToPath: string
          returnToCurrentPath?: never
      }
    | {
          returnToPath?: never
          returnToCurrentPath: boolean
      }

export async function getUserOrRedirect(redirectOptions?: RedirectOptions): Promise<UserFromToken> {
    const user = await getUser()
    if (user) {
        return user
    } else {
        redirectToLogin(redirectOptions)
        throw new Error('Redirecting to login')
    }
}

export async function getUser(): Promise<UserFromToken | undefined> {
    const accessToken = getAccessToken()
    if (accessToken) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return user
        }
    }
    return undefined
}

export function getAccessToken(): string | undefined {
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
    if (
        req.nextUrl.pathname === CALLBACK_PATH ||
        req.nextUrl.pathname === LOGOUT_PATH ||
        req.nextUrl.pathname === USERINFO_PATH
    ) {
        // Don't do anything for the callback, logout, or userinfo paths, as they will modify the cookies themselves
        return getNextResponse(req)
    }

    const accessToken = req.cookies.get(ACCESS_TOKEN_COOKIE_NAME)?.value
    const refreshToken = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value
    const activeOrgId = req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)?.value

    // If we are authenticated, we can continue
    if (accessToken) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return getNextResponse(req)
        }
    }

    // Otherwise, we need to refresh the access token
    if (refreshToken) {
        const response = await refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId)
        if (response.error === 'unexpected') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (response.error === 'unauthorized') {
            const response = getNextResponse(req)
            response.cookies.delete(ACCESS_TOKEN_COOKIE_NAME)
            response.cookies.delete(REFRESH_TOKEN_COOKIE_NAME)
            return response
        } else {
            const nextResponse = getNextResponse(req, response.accessToken)
            nextResponse.cookies.set(ACCESS_TOKEN_COOKIE_NAME, response.accessToken, COOKIE_OPTIONS)
            nextResponse.cookies.set(REFRESH_TOKEN_COOKIE_NAME, response.refreshToken, COOKIE_OPTIONS)
            return nextResponse
        }
    }

    return getNextResponse(req)
}

function getNextResponse(request: NextRequest, newAccessToken?: string) {
    const headers = new Headers(request.headers)
    headers.set(CUSTOM_HEADER_FOR_URL, request.nextUrl.toString())
    headers.set(CUSTOM_HEADER_FOR_PATH, request.nextUrl.pathname + request.nextUrl.search)
    if (newAccessToken) {
        headers.set(CUSTOM_HEADER_FOR_ACCESS_TOKEN, newAccessToken)
    }
    return NextResponse.next({
        request: {
            headers,
        },
    })
}

export type RouteHandlerArgs = {
    postLoginRedirectPathFn?: (req: NextRequest) => string
    getDefaultActiveOrgId?: (req: NextRequest, user: UserFromToken) => string | undefined
}

export function getRouteHandlers(args?: RouteHandlerArgs) {
    function loginGetHandler(req: NextRequest) {
        const handlerResponse = genericLoginGetHandler({
            returnToPath: req.nextUrl.searchParams.get('return_to_path') || undefined,
        })
        return toResponse(handlerResponse)
    }

    function signupGetHandler(req: NextRequest) {
        const handlerResponse = genericSignupGetHandler({
            returnToPath: req.nextUrl.searchParams.get('return_to_path') || undefined,
        })
        return toResponse(handlerResponse)
    }

    async function callbackGetHandler(req: NextRequest) {
        const queryParams = req.nextUrl.searchParams

        // To share code between pages & app router, we need to wrap the postLoginRedirectPathFn
        // so the result is a function that takes no arguments
        let wrappedPostLoginRedirectPathFn: (() => string) | undefined = undefined
        const postLoginRedirectPathFn = args?.postLoginRedirectPathFn
        if (postLoginRedirectPathFn) {
            wrappedPostLoginRedirectPathFn = () => postLoginRedirectPathFn(req)
        }

        let wrappedGetDefaultActiveOrgId: ((user: UserFromToken) => string | undefined) | undefined = undefined
        const getDefaultActiveOrgId = args?.getDefaultActiveOrgId
        if (getDefaultActiveOrgId) {
            wrappedGetDefaultActiveOrgId = (user: UserFromToken) => getDefaultActiveOrgId(req, user)
        }

        let handlerResponse = await genericCallbackGetHandler({
            returnToPathFromCookie: req.cookies.get(RETURN_TO_PATH_COOKIE_NAME)?.value,
            activeOrgIdFromCookie: req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)?.value,
            stateFromCookie: req.cookies.get(STATE_COOKIE_NAME)?.value,
            stateFromQuery: queryParams.get('state') || undefined,
            codeFromQuery: queryParams.get('code') || undefined,
            postLoginRedirectPathFn: wrappedPostLoginRedirectPathFn,
            getDefaultActiveOrgId: wrappedGetDefaultActiveOrgId,
        })

        return toResponse(handlerResponse)
    }

    async function userinfoGetHandler(req: NextRequest) {
        const handlerResponse = await genericUserinfoGetHandler({
            refreshToken: req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value,
            activeOrgId: req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)?.value,
        })
        return toResponse(handlerResponse)
    }

    async function logoutGetHandler(req: NextRequest) {
        let wrappedPostLoginRedirectPathFn: (() => string) | undefined = undefined
        const postLoginRedirectPathFn = args?.postLoginRedirectPathFn
        if (postLoginRedirectPathFn) {
            wrappedPostLoginRedirectPathFn = () => postLoginRedirectPathFn(req)
        }

        const handlerResponse = await genericLogoutGetHandler({
            refreshToken: req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value,
            activeOrgId: req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)?.value,
            postLoginRedirectPathFn: wrappedPostLoginRedirectPathFn,
        })
        return toResponse(handlerResponse)
    }

    async function logoutPostHandler(req: NextRequest) {
        const handlerResponse = await genericLogoutPostHandler({
            refreshToken: req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value,
        })
        return toResponse(handlerResponse)
    }

    async function setActiveOrgHandler(req: NextRequest) {
        const handlerResponse = await genericSetActiveOrgHandler({
            refreshToken: req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)?.value,
            activeOrgId: req.nextUrl.searchParams.get('active_org_id') || undefined,
        })
        return toResponse(handlerResponse)
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
        } else if (params.slug === 'set-active-org') {
            return setActiveOrgHandler(req)
        } else {
            return new Response('', { status: 404 })
        }
    }

    return {
        getRouteHandler,
        postRouteHandler,
    }
}

function redirectToLogin(redirectOptions?: RedirectOptions) {
    if (!redirectOptions) {
        redirect(LOGIN_PATH)
    } else if (redirectOptions.returnToPath) {
        const loginPath = LOGIN_PATH + '?return_to_path=' + encodeURI(redirectOptions.returnToPath)
        redirect(loginPath)
    } else if (redirectOptions.returnToCurrentPath) {
        const encodedPath = getUrlEncodedRedirectPathForCurrentPath()
        if (encodedPath) {
            const loginPath = LOGIN_PATH + '?return_to_path=' + encodedPath
            redirect(loginPath)
        } else {
            console.warn('Could not get current URL to redirect to')
            redirect(LOGIN_PATH)
        }
    }
}

export function getUrlEncodedRedirectPathForCurrentPath(): string | undefined {
    const path = getCurrentPath()
    if (!path) {
        return undefined
    }

    return encodeURIComponent(path)
}

// It's really common to want to redirect back to the exact location you are on
// Next.js unfortunately makes this pretty hard, as server components don't have access to the path
// The only good way to do this is to set up some middleware and pass the path down from the middleware
// Since we have the requirement that people set up middleware with us anyway, it's easy for us to expose
// this functionality
export function getCurrentPath(): string | undefined {
    const path = headers().get(CUSTOM_HEADER_FOR_PATH)
    if (!path) {
        console.warn(
            'Attempting to redirect to the current path, but we could not find the current path in the headers. Is the middleware set up?'
        )
        return undefined
    } else {
        return path
    }
}

/**
 * @deprecated since version 0.1.0
 * Use getCurrentPath instead
 */
export function getCurrentUrl(): string | undefined {
    console.warn('getCurrentUrl is deprecated in favor of getCurrentPath.')
    const url = headers().get(CUSTOM_HEADER_FOR_URL)
    if (!url) {
        console.warn(
            'Attempting to redirect to the current URL, but we could not find the current URL in the headers. Is the middleware set up?'
        )
        return undefined
    } else {
        return url
    }
}

function toResponse(handlerResponse: GenericResponse): Response {
    if (handlerResponse.responseType === 'none') {
        return new Response(null, {
            status: handlerResponse.status,
            headers: handlerResponse.headers,
        })
    } else if (handlerResponse.responseType === 'json') {
        return new Response(JSON.stringify(handlerResponse.body), {
            status: handlerResponse.status,
            headers: handlerResponse.headers,
        })
    } else if (handlerResponse.responseType === 'text') {
        return new Response(handlerResponse.body, {
            status: handlerResponse.status,
            headers: handlerResponse.headers,
        })
    } else {
        assertNever(handlerResponse)
    }
}
