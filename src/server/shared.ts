import { ResponseCookie } from 'next/dist/compiled/@edge-runtime/cookies'
import { InternalUser, toUser, UserFromToken } from '../user'
import { ConfigurationException, UnauthorizedException } from './exceptions'
import * as jose from 'jose'

type RefreshAndAccessTokens = {
    refreshToken: string
    accessToken: string
    error: 'none'
}

type RefreshAndAccessTokensUnauthorizedError = {
    error: 'unauthorized'
}

type RefreshAndAccessTokensUnexpectedError = {
    error: 'unexpected'
}

export type RefreshTokenResponse =
    | RefreshAndAccessTokens
    | RefreshAndAccessTokensUnauthorizedError
    | RefreshAndAccessTokensUnexpectedError

export const LOGIN_PATH = '/api/auth/login'
export const CALLBACK_PATH = '/api/auth/callback'
export const USERINFO_PATH = '/api/auth/userinfo'
export const LOGOUT_PATH = '/api/auth/logout'
export const ACCESS_TOKEN_COOKIE_NAME = '__pa_at'
export const REFRESH_TOKEN_COOKIE_NAME = '__pa_rt'
export const STATE_COOKIE_NAME = '__pa_state'
export const CUSTOM_HEADER_FOR_ACCESS_TOKEN = 'x-propelauth-access-token'
export const CUSTOM_HEADER_FOR_URL = 'x-propelauth-current-url'
export const CUSTOM_HEADER_FOR_PATH = 'x-propelauth-current-path'
export const RETURN_TO_PATH_COOKIE_NAME = '__pa_return_to_path'

export const COOKIE_OPTIONS: Partial<ResponseCookie> = {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
}

export function getAuthUrlOrigin() {
    return getAuthUrl().origin
}

export function getAuthUrl() {
    const authUrl = process.env.NEXT_PUBLIC_AUTH_URL
    if (!authUrl) {
        throw new Error('NEXT_PUBLIC_AUTH_URL is not set')
    }
    return new URL(authUrl)
}

export function getRedirectUri() {
    const redirectUri = process.env.PROPELAUTH_REDIRECT_URI
    if (!redirectUri) {
        throw new Error('PROPELAUTH_REDIRECT_URI is not set')
    }
    return redirectUri
}

export function getIntegrationApiKey() {
    const integrationApiKey = process.env.PROPELAUTH_API_KEY
    if (!integrationApiKey) {
        throw new Error('PROPELAUTH_API_KEY is not set')
    }
    return integrationApiKey
}

export function getVerifierKey() {
    const verifierKey = process.env.PROPELAUTH_VERIFIER_KEY
    if (!verifierKey) {
        throw new Error('PROPELAUTH_VERIFIER_KEY is not set')
    }
    return verifierKey.replace(/\\n/g, '\n')
}

export async function refreshTokenWithAccessAndRefreshToken(
    refreshToken: string,
    activeOrgId?: string
): Promise<RefreshTokenResponse> {
    const body = {
        refresh_token: refreshToken,
    }

    const queryParams = new URLSearchParams()
    if (activeOrgId) {
        queryParams.set('with_active_org_support', 'true')
        queryParams.set('active_org_id', activeOrgId)
    }

    const url = `${getAuthUrlOrigin()}/api/backend/v1/refresh_token?${queryParams.toString()}`
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify(body),
        headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer ' + getIntegrationApiKey(),
        },
    })

    if (response.ok) {
        const data = await response.json()
        const newRefreshToken = data.refresh_token
        const { access_token: accessToken, expires_at_seconds: expiresAtSeconds } = data.access_token

        return {
            refreshToken: newRefreshToken,
            accessToken,
            error: 'none',
        }
    } else if (response.status === 400 || response.status === 401) {
        return { error: 'unauthorized' }
    } else {
        return { error: 'unexpected' }
    }
}

export async function validateAccessTokenOrUndefined(
    accessToken: string | undefined
): Promise<UserFromToken | undefined> {
    try {
        return await validateAccessToken(accessToken)
    } catch (err) {
        if (err instanceof ConfigurationException) {
            throw err
        } else if (err instanceof UnauthorizedException) {
            return undefined
        } else {
            console.info('Error validating access token', err)
            return undefined
        }
    }
}

export async function validateAccessToken(accessToken: string | undefined): Promise<UserFromToken> {
    let publicKey
    try {
        publicKey = await jose.importSPKI(getVerifierKey(), 'RS256')
    } catch (err) {
        console.error("Verifier key is invalid. Make sure it's specified correctly, including the newlines.", err)
        throw new ConfigurationException('Invalid verifier key')
    }

    if (!accessToken) {
        throw new UnauthorizedException('No access token provided')
    }

    let accessTokenWithoutBearer = accessToken
    if (accessToken.toLowerCase().startsWith('bearer ')) {
        accessTokenWithoutBearer = accessToken.substring('bearer '.length)
    }

    try {
        const { payload } = await jose.jwtVerify(accessTokenWithoutBearer, publicKey, {
            issuer: getAuthUrlOrigin(),
            algorithms: ['RS256'],
        })

        return toUser(<InternalUser>payload)
    } catch (e) {
        if (e instanceof Error) {
            throw new UnauthorizedException(e.message)
        } else {
            throw new UnauthorizedException('Unable to decode jwt')
        }
    }
}
