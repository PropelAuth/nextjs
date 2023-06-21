import { getServerActions } from "./server-actions"
import { User } from "../user"
import { validateAuthUrl } from "./validators"

export type InitializeAuthOptions = {
    authUrl: string
    redirectUri: string
    integrationApiKey: string
    verifierKey: string
    postLoginRedirectPathFn?: (user: User) => string
}

export function initializeAuth(opts: InitializeAuthOptions) {
    const authUrl = validateAuthUrl(opts.authUrl).origin
    const postLoginPathFn =
        opts.postLoginRedirectPathFn ||
        function () {
            return "/"
        }

    return getServerActions({
        authUrlOrigin: authUrl,
        verifierKey: opts.verifierKey,
        redirectUri: opts.redirectUri,
        integrationApiKey: opts.integrationApiKey,
        postLoginPathFn,
    })
}
