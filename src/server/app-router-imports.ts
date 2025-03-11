// Different configurations of Next unfortunately have different requirements here.
// Ideally, all customers would use the newer syntax without `.js` but certain configurations
// need the `.js` extension. This file is a workaround to support both configurations.

import type { redirect as RedirectFn } from 'next/navigation'
import type { cookies as CookiesFn, headers as HeadersFn } from 'next/headers'
import type { NextRequest as TNextRequest, NextResponse as TNextResponse } from 'next/server'

let redirect: typeof RedirectFn
let cookies: typeof CookiesFn
let headers: typeof HeadersFn
let NextRequest: typeof TNextRequest
let NextResponse: typeof TNextResponse

try {
    // Modern syntax (Next 13+)
    ;({ redirect } = require('next/navigation'))
} catch {
    try {
        // Fallback for older Next setups that might need `.js`
        ;({ redirect } = require('next/navigation.js'))
    } catch {
        throw new Error('Neither "next/navigation" nor "next/navigation.js" could be imported.')
    }
}

try {
    ;({ cookies, headers } = require('next/headers'))
} catch {
    try {
        ;({ cookies, headers } = require('next/headers.js'))
    } catch {
        throw new Error('Neither "next/headers" nor "next/headers.js" could be imported.')
    }
}

try {
    ;({ NextRequest, NextResponse } = require('next/server'))
} catch {
    try {
        ;({ NextRequest, NextResponse } = require('next/server.js'))
    } catch {
        throw new Error('Neither "next/server" nor "next/server.js" could be imported.')
    }
}

export { redirect, cookies, headers, NextRequest, NextResponse }
export type { TNextRequest, TNextResponse }
