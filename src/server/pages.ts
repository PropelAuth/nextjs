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
import { UserFromToken } from '../user'

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
        if (response.error === 'unexpected') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (response.error === 'unauthorized') {
            props.res.setHeader('Set-Cookie', [
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`,
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`,
            ])
            return {
                user: undefined,
                accessToken: undefined,
            }
        } else {
            const user = await validateAccessToken(response.accessToken)
            props.res.setHeader('Set-Cookie', [
                `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=${sameSite}`,
                `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=${sameSite}`,
            ])
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
        if (response.error === 'unexpected') {
            throw new Error('Unexpected error while refreshing access token')
        } else if (response.error === 'unauthorized') {
            res.setHeader('Set-Cookie', [
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`,
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`,
            ])
            return {
                user: undefined,
                accessToken: undefined,
            }
        } else {
            const user = await validateAccessToken(response.accessToken)
            res.setHeader('Set-Cookie', [
                `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=${sameSite}`,
                `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=${sameSite}`,
            ])
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
