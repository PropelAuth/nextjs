export class UnauthorizedException extends Error {
    readonly message: string
    readonly status: number

    constructor(message: string) {
        super(message)
        this.message = message
        this.status = 401
    }
}

export class RefreshRateLimitedException extends Error {
    readonly message: string
    readonly status: number
    readonly retryAfter?: string

    constructor(message: string, retryAfter?: string) {
        super(message)
        this.message = message
        this.status = 429
        this.retryAfter = retryAfter
    }
}

export class ConfigurationException extends Error {
    readonly message: string
    readonly status: number

    constructor(message: string) {
        super(message)
        this.message = message
        this.status = 500
    }
}
