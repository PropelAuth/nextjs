import { GetServerSidePropsContext, NextApiRequest, NextApiResponse } from 'next'
import {
    ACCESS_TOKEN_COOKIE_NAME,
    getSameSiteCookieValue,
    REFRESH_TOKEN_COOKIE_NAME,
    refreshTokenWithAccessAndRefreshToken,
    validateAccessToken,
    validateAccessTokenOrUndefined,
} from './shared'
import { ACTIVE_ORG_ID_COOKIE_NAME } from '../shared'
import {
    AUTH_CACHE_CONTROL,
    AuthCookie,
    authCookieDeletion,
    SameSiteCookieValue,
    toSetCookieHeaderValues,
} from './auth-response'
import { UserFromToken } from '../user'

type SetCookieCapableResponse = {
    getHeader(name: string): number | string | string[] | undefined
    setHeader(name: string, value: string | string[]): unknown
}

function appendAuthCookiesToNodeResponse(res: SetCookieCapableResponse, cookies: AuthCookie[]): void {
    const existing = res.getHeader('Set-Cookie')
    const existingValues = existing === undefined ? [] : [existing].flat().map(String)
    res.setHeader('Set-Cookie', [...existingValues, ...toSetCookieHeaderValues(cookies)])
    res.setHeader('Cache-Control', AUTH_CACHE_CONTROL)
}

function refreshedTokenCookies(
    accessToken: string,
    refreshToken: string,
    sameSite: SameSiteCookieValue
): AuthCookie[] {
    return [
        { name: ACCESS_TOKEN_COOKIE_NAME, value: accessToken, sameSite },
        { name: REFRESH_TOKEN_COOKIE_NAME, value: refreshToken, sameSite },
    ]
}

function tokenCookieDeletions(sameSite: SameSiteCookieValue): AuthCookie[] {
    return [
        authCookieDeletion(ACCESS_TOKEN_COOKIE_NAME, sameSite),
        authCookieDeletion(REFRESH_TOKEN_COOKIE_NAME, sameSite),
    ]
}

export type AuthInfo =
    | {
          user: UserFromToken
          accessToken: string
      }
    | {
          user: undefined
          accessToken: undefined
      }

export async function getAuthInfoFromServerSideProps(
    props: GetServerSidePropsContext,
    forceRefresh: boolean = false
): Promise<AuthInfo> {
    const accessToken = props.req.cookies[ACCESS_TOKEN_COOKIE_NAME]
    const refreshToken = props.req.cookies[REFRESH_TOKEN_COOKIE_NAME]
    const activeOrgId = props.req.cookies[ACTIVE_ORG_ID_COOKIE_NAME]
    const sameSite = getSameSiteCookieValue()

    // If we are authenticated, we can continue
    if (accessToken && !forceRefresh) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return {
                user,
                accessToken,
            }
        }
    }

    // Otherwise, we need to refresh the access token
    if (refreshToken) {
        const response = await refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId)
        if (response.error === 'unexpected' || response.error === 'rate_limited') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (response.error === 'unauthorized') {
            appendAuthCookiesToNodeResponse(props.res, tokenCookieDeletions(sameSite))
            return {
                user: undefined,
                accessToken: undefined,
            }
        } else {
            const user = await validateAccessToken(response.accessToken)
            appendAuthCookiesToNodeResponse(
                props.res,
                refreshedTokenCookies(response.accessToken, response.refreshToken, sameSite)
            )
            return {
                user,
                accessToken: response.accessToken,
            }
        }
    }

    return {
        user: undefined,
        accessToken: undefined,
    }
}

export async function getUserFromServerSideProps(props: GetServerSidePropsContext, forceRefresh: boolean = false) {
    const { user } = await getAuthInfoFromServerSideProps(props, forceRefresh)
    return user
}

export async function getAuthInfoFromApiRouteRequest(
    req: NextApiRequest,
    res: NextApiResponse,
    forceRefresh: boolean = false
): Promise<AuthInfo> {
    const accessToken = req.cookies[ACCESS_TOKEN_COOKIE_NAME]
    const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME]
    const activeOrgId = req.cookies[ACTIVE_ORG_ID_COOKIE_NAME]
    const sameSite = getSameSiteCookieValue()

    // If we are authenticated, we can continue
    if (accessToken && !forceRefresh) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return {
                user,
                accessToken,
            }
        }
    }

    // Otherwise, we need to refresh the access token
    if (refreshToken) {
        const response = await refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId)
        if (response.error === 'unexpected' || response.error === 'rate_limited') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (response.error === 'unauthorized') {
            appendAuthCookiesToNodeResponse(res, tokenCookieDeletions(sameSite))
            return {
                user: undefined,
                accessToken: undefined,
            }
        } else {
            const user = await validateAccessToken(response.accessToken)
            appendAuthCookiesToNodeResponse(
                res,
                refreshedTokenCookies(response.accessToken, response.refreshToken, sameSite)
            )
            return {
                user,
                accessToken: response.accessToken,
            }
        }
    }

    return {
        user: undefined,
        accessToken: undefined,
    }
}

export async function getUserFromApiRouteRequest(
    req: NextApiRequest,
    res: NextApiResponse,
    forceRefresh: boolean = false
) {
    const { user } = await getAuthInfoFromApiRouteRequest(req, res, forceRefresh)
    return user
}
