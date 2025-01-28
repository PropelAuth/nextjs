import { NextResponse } from 'next/server'

export class AuthHookResponse {
    private constructor(
        private readonly type: 'continue' | 'reject',
        private readonly response?: NextResponse
    ) {}

    static continue(): AuthHookResponse {
        return new AuthHookResponse('continue')
    }

    static reject(response: NextResponse): AuthHookResponse {
        return new AuthHookResponse('reject', response)
    }

    shouldContinue(): boolean {
        return this.type === 'continue'
    }

    getResponse(): NextResponse | undefined {
        return this.response
    }
}
