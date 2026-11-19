import { stringifySetCookie } from 'cookie'

export type SameSiteCookieValue = 'none' | 'lax' | 'strict'

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
