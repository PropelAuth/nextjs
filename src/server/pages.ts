import {GetServerSidePropsContext, NextApiRequest, NextApiResponse} from "next";
import {
    ACCESS_TOKEN_COOKIE_NAME,
    REFRESH_TOKEN_COOKIE_NAME,
    refreshTokenWithAccessAndRefreshToken, validateAccessToken,
    validateAccessTokenOrUndefined
} from "./shared";

export async function getUserFromServerSideProps(props: GetServerSidePropsContext) {
    const accessToken = props.req.cookies[ACCESS_TOKEN_COOKIE_NAME]
    const refreshToken = props.req.cookies[REFRESH_TOKEN_COOKIE_NAME]

    // If we are authenticated, we can continue
    if (accessToken) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return user
        }
    }

    // Otherwise, we need to refresh the access token
    if (refreshToken) {
        const response = await refreshTokenWithAccessAndRefreshToken(refreshToken)
        if (response.error === "unexpected") {
            throw new Error("Unexpected error while refreshing access token")
        } else if (response.error === "unauthorized") {
            props.res.setHeader("Set-Cookie", [
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
            ])
            return undefined
        } else {
            const user = await validateAccessToken(response.accessToken)
            props.res.setHeader("Set-Cookie", [
                `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
                `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
            ])
            return user
        }
    }

    return undefined
}

export async function getUserFromApiRouteRequest(req: NextApiRequest, res: NextApiResponse) {
    const accessToken = req.cookies[ACCESS_TOKEN_COOKIE_NAME]
    const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME]

    // If we are authenticated, we can continue
    if (accessToken) {
        const user = await validateAccessTokenOrUndefined(accessToken)
        if (user) {
            return user
        }
    }

    // Otherwise, we need to refresh the access token
    if (refreshToken) {
        const response = await refreshTokenWithAccessAndRefreshToken(refreshToken)
        if (response.error === "unexpected") {
            throw new Error("Unexpected error while refreshing access token")
        } else if (response.error === "unauthorized") {
            res.setHeader("Set-Cookie", [
                `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
                `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
            ])
            return undefined
        } else {
            const user = await validateAccessToken(response.accessToken)
            res.setHeader("Set-Cookie", [
                `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
                `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
            ])
            return user
        }
    }

    return undefined

}