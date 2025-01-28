import { NextRequest, NextResponse } from 'next/server'
import {
    ACCESS_TOKEN_COOKIE_NAME,
    CALLBACK_PATH,
    COOKIE_OPTIONS,
    LOGOUT_PATH,
    REFRESH_TOKEN_COOKIE_NAME,
    USERINFO_PATH,
    getSameSiteCookieValue,
    refreshTokenWithAccessAndRefreshToken,
    validateAccessToken,
    validateAccessTokenOrUndefined,
} from '../shared'
import { ACTIVE_ORG_ID_COOKIE_NAME } from '../../shared'
import { getNextResponse } from '../app-router'
import { UserFromToken } from '../../user'
import { AuthHookResponse } from './auth-hook-response'

export type PropelAuthMiddlewareOptions = {
    afterAuthHook?: (req: NextRequest, res: NextResponse, user?: UserFromToken) => Promise<AuthHookResponse>
}

// Purpose of this middleware is just to keep the access token cookie alive
// In an ideal world, this could be done in `getUser`, however, you can't
//   set a cookie in a server component.
// There also doesn't seem to be any way right now to set a cookie in a
//   middleware and pass it forward (you can only set them on the response).
// You CAN, however, pass in custom headers,
//   so we'll use CUSTOM_HEADER_FOR_ACCESS_TOKEN as a workaround
export function buildAuthMiddleware(options?: PropelAuthMiddlewareOptions): (req: NextRequest) => Promise<Response> {
    return async (req: NextRequest) => {
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
                const nextResponse = getNextResponse(req)
                return await handlePostAuthHook(req, nextResponse, user, options)
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
                return await handlePostAuthHook(req, response, undefined, options)
            } else {
                const sameSite = getSameSiteCookieValue()
                const nextResponse = getNextResponse(req, response.accessToken)
                nextResponse.cookies.set(ACCESS_TOKEN_COOKIE_NAME, response.accessToken, {
                    ...COOKIE_OPTIONS,
                    sameSite,
                })
                nextResponse.cookies.set(REFRESH_TOKEN_COOKIE_NAME, response.refreshToken, {
                    ...COOKIE_OPTIONS,
                    sameSite,
                })
                const user = await validateAccessToken(response.accessToken)
                return await handlePostAuthHook(req, nextResponse, user, options)
            }
        }

        const res = getNextResponse(req)
        return await handlePostAuthHook(req, res, undefined, options)
    }
}

const handlePostAuthHook = async (
    req: NextRequest,
    res: NextResponse,
    user?: UserFromToken,
    options?: PropelAuthMiddlewareOptions
): Promise<NextResponse> => {
    if (options?.afterAuthHook) {
        const hookResponse = await options.afterAuthHook(req, res, user)
        if (hookResponse instanceof AuthHookResponse) {
            if (!hookResponse.shouldContinue()) {
                return hookResponse.getResponse() ?? res
            }
        } else {
            console.warn('afterAuthHook did not return a AuthHookResponse, continuing')
        }
    }
    return res
}
