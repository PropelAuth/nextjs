import { stringifySetCookie } from 'cookie'

export type SameSiteCookieValue = 'none' | 'lax' | 'strict'

export const AUTH_CACHE_CONTROL = 'private, no-cache, no-store, max-age=0, must-revalidate'

export function unexpectedErrorResponse(): Response {
    return new Response('Unexpected error', { status: 500 })
}

export function unauthorizedResponse(headers?: Headers): Response {
    return new Response('Unauthorized', { status: 401, headers })
}

export function rateLimitedResponse(retryAfter: string | undefined): Response {
    const headers = new Headers()
    if (retryAfter) {
        headers.set('Retry-After', retryAfter)
    }
    return new Response('Too many requests', { status: 429, headers })
}

export type AuthCookie = {
    name: string
    value: string
    sameSite: SameSiteCookieValue
    maxAgeSeconds?: number
}

export function serializeAuthCookie({ name, value, sameSite, maxAgeSeconds }: AuthCookie): string {
    return stringifySetCookie({
        name,
        value,
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite,
        maxAge: maxAgeSeconds,
    })
}

export function authCookieDeletion(name: string, sameSite: SameSiteCookieValue): AuthCookie {
    return { name, value: '', sameSite, maxAgeSeconds: 0 }
}

export function appendAuthCookies(headers: Headers, cookies: AuthCookie[]): void {
    for (const cookie of cookies) {
        headers.append('Set-Cookie', serializeAuthCookie(cookie))
    }
}

export function toSetCookieHeaderValues(cookies: AuthCookie[]): string[] {
    return cookies.map(serializeAuthCookie)
}

export type AuthCookieOptions = {
    httpOnly: true
    secure: true
    path: '/'
    sameSite: SameSiteCookieValue
}

// NextResponse.cookies.set encodes the value itself, so pass it the raw value.
export function authCookieOptions(sameSite: SameSiteCookieValue): AuthCookieOptions {
    return { httpOnly: true, secure: true, path: '/', sameSite }
}
