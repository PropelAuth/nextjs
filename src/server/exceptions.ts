export class UnauthorizedException extends Error {
    readonly message: string
    readonly status: number

    constructor(message: string) {
        super(message)
        this.message = message
        this.status = 401
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
