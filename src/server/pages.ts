import { GetServerSidePropsContext, NextApiRequest, NextApiResponse } from 'next'
import {
    ACCESS_TOKEN_COOKIE_NAME,
    assertNever,
    REFRESH_TOKEN_COOKIE_NAME,
    refreshTokenWithAccessAndRefreshToken,
    RETURN_TO_PATH_COOKIE_NAME,
    STATE_COOKIE_NAME,
    validateAccessToken,
    validateAccessTokenOrUndefined,
} from './shared'
import { ACTIVE_ORG_ID_COOKIE_NAME } from '../shared'
import { UserFromToken } from '../user'
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
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
            ])
            return {
                user: undefined,
                accessToken: undefined,
            }
        } else {
            const user = await validateAccessToken(response.accessToken)
            props.res.setHeader('Set-Cookie', [
                `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
                `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
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
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
            ])
            return {
                user: undefined,
                accessToken: undefined,
            }
        } else {
            const user = await validateAccessToken(response.accessToken)
            res.setHeader('Set-Cookie', [
                `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
                `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
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

export type RouteHandlerPagesArgs = {
    postLoginRedirectPathFn?: (req: NextApiRequest) => string
    getDefaultActiveOrgId?: (req: NextApiRequest, user: UserFromToken) => string | undefined
}

export function getRouteHandlers(args?: RouteHandlerPagesArgs) {
    function loginGetHandler(req: NextApiRequest, res: NextApiResponse) {
        const handlerResponse = genericLoginGetHandler({
            returnToPath: getStringQueryParameter(req, 'return_to_path'),
        })
        returnResponse(handlerResponse, res)
    }

    function signupGetHandler(req: NextApiRequest, res: NextApiResponse) {
        const handlerResponse = genericSignupGetHandler({
            returnToPath: getStringQueryParameter(req, 'return_to_path'),
        })
        returnResponse(handlerResponse, res)
    }

    async function callbackGetHandler(req: NextApiRequest, res: NextApiResponse) {
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
            returnToPathFromCookie: getCookieValue(req, RETURN_TO_PATH_COOKIE_NAME),
            activeOrgIdFromCookie: getCookieValue(req, ACTIVE_ORG_ID_COOKIE_NAME),
            stateFromCookie: getCookieValue(req, STATE_COOKIE_NAME),
            stateFromQuery: getStringQueryParameter(req, 'state'),
            codeFromQuery: getStringQueryParameter(req, 'code'),
            postLoginRedirectPathFn: wrappedPostLoginRedirectPathFn,
            getDefaultActiveOrgId: wrappedGetDefaultActiveOrgId,
        })
        returnResponse(handlerResponse, res)
    }

    async function userinfoGetHandler(req: NextApiRequest, res: NextApiResponse) {
        const handlerResponse = await genericUserinfoGetHandler({
            refreshToken: getCookieValue(req, REFRESH_TOKEN_COOKIE_NAME),
            activeOrgId: getCookieValue(req, ACTIVE_ORG_ID_COOKIE_NAME),
        })
        returnResponse(handlerResponse, res)
    }

    async function logoutGetHandler(req: NextApiRequest, res: NextApiResponse) {
        let wrappedPostLoginRedirectPathFn: (() => string) | undefined = undefined
        const postLoginRedirectPathFn = args?.postLoginRedirectPathFn
        if (postLoginRedirectPathFn) {
            wrappedPostLoginRedirectPathFn = () => postLoginRedirectPathFn(req)
        }

        const handlerResponse = await genericLogoutGetHandler({
            refreshToken: getCookieValue(req, REFRESH_TOKEN_COOKIE_NAME),
            activeOrgId: getCookieValue(req, ACTIVE_ORG_ID_COOKIE_NAME),
            postLoginRedirectPathFn: wrappedPostLoginRedirectPathFn,
        })
        returnResponse(handlerResponse, res)
    }

    async function logoutPostHandler(req: NextApiRequest, res: NextApiResponse) {
        const handlerResponse = await genericLogoutPostHandler({
            refreshToken: getCookieValue(req, REFRESH_TOKEN_COOKIE_NAME),
        })
        returnResponse(handlerResponse, res)
    }

    async function setActiveOrgHandler(req: NextApiRequest, res: NextApiResponse) {
        const handlerResponse = await genericSetActiveOrgHandler({
            refreshToken: getCookieValue(req, REFRESH_TOKEN_COOKIE_NAME),
            activeOrgId: getStringQueryParameter(req, 'active_org_id'),
        })
        returnResponse(handlerResponse, res)
    }

    async function getRouteHandler(req: NextApiRequest, res: NextApiResponse) {
        const slug = req.query.slug
        if (slug === 'login') {
            loginGetHandler(req, res)
        } else if (slug === 'signup') {
            signupGetHandler(req, res)
        } else if (slug === 'callback') {
            await callbackGetHandler(req, res)
        } else if (slug === 'userinfo') {
            await userinfoGetHandler(req, res)
        } else if (slug === 'logout') {
            await logoutGetHandler(req, res)
        } else {
            res.status(404).end()
        }
    }

    async function postRouteHandler(req: NextApiRequest, res: NextApiResponse) {
        const slug = req.query.slug
        if (slug === 'logout') {
            await logoutPostHandler(req, res)
        } else if (slug === 'set-active-org') {
            await setActiveOrgHandler(req, res)
        } else {
            res.status(404).end()
        }
    }

    async function routeHandler(req: NextApiRequest, res: NextApiResponse) {
        if (req.method === 'GET') {
            await getRouteHandler(req, res)
        } else if (req.method === 'POST') {
            await postRouteHandler(req, res)
        } else {
            res.status(405).end()
        }
    }

    return routeHandler
}

function returnResponse(handlerResponse: GenericResponse, res: NextApiResponse) {
    for (const [key, value] of handlerResponse.headers) {
        res.appendHeader(key, value)
    }

    if (handlerResponse.responseType === 'none') {
        res.status(handlerResponse.status).end()
    } else if (handlerResponse.responseType === 'json') {
        res.status(handlerResponse.status).json(handlerResponse.body)
    } else if (handlerResponse.responseType === 'text') {
        res.status(handlerResponse.status).send(handlerResponse.body)
    } else {
        assertNever(handlerResponse)
    }
}

function getStringQueryParameter(req: NextApiRequest, name: string): string | undefined {
    const value = req.query[name]
    if (value && typeof value === 'string') {
        return value
    } else {
        return undefined
    }
}

function getCookieValue(req: NextApiRequest, name: string): string | undefined {
    return req.cookies[name]
}
