export enum SocialLoginProvider {
    Google = 'Google',
    GitHub = 'GitHub',
    Microsoft = 'Microsoft',
    Slack = 'Slack',
    LinkedIn = 'LinkedIn',
    Salesforce = 'Salesforce',
    Xero = 'Xero',
    QuickBooksOnline = 'QuickBooks Online',
}

export enum SamlLoginProvider {
    Google = 'Google',
    Rippling = 'Rippling',
    OneLogin = 'OneLogin',
    JumpCloud = 'JumpCloud',
    Okta = 'Okta',
    Azure = 'Azure',
    Duo = 'Duo',
    Generic = 'Generic',
}

type InternalPasswordLoginMethod = {
    login_method: 'password'
}

type InternalMagicLinkLoginMethod = {
    login_method: 'magic_link'
}

type InternalSocialSsoLoginMethod = {
    login_method: 'social_sso'
    provider: SocialLoginProvider
}

type InternalEmailConfirmationLinkLoginMethod = {
    login_method: 'email_confirmation_link'
}

type InternalSamlSsoLoginMethod = {
    login_method: 'saml_sso'
    provider: SamlLoginProvider
    org_id: string
}

type InternalImpersonationLoginMethod = {
    login_method: 'impersonation'
}

type InternalGeneratedFromBackendApiLoginMethod = {
    login_method: 'generated_from_backend_api'
}

type InternalUnknownLoginMethod = {
    login_method: 'unknown'
}

export type InternalLoginMethod =
    | InternalPasswordLoginMethod
    | InternalMagicLinkLoginMethod
    | InternalSocialSsoLoginMethod
    | InternalEmailConfirmationLinkLoginMethod
    | InternalSamlSsoLoginMethod
    | InternalImpersonationLoginMethod
    | InternalGeneratedFromBackendApiLoginMethod
    | InternalUnknownLoginMethod

type PasswordLoginMethod = {
    loginMethod: 'password'
}

type MagicLinkLoginMethod = {
    loginMethod: 'magic_link'
}

type SocialSsoLoginMethod = {
    loginMethod: 'social_sso'
    provider: SocialLoginProvider
}

type EmailConfirmationLinkLoginMethod = {
    loginMethod: 'email_confirmation_link'
}

type SamlSsoLoginMethod = {
    loginMethod: 'saml_sso'
    provider: SamlLoginProvider
    orgId: string
}

type ImpersonationLoginMethod = {
    loginMethod: 'impersonation'
}

type GeneratedFromBackendApiLoginMethod = {
    loginMethod: 'generated_from_backend_api'
}

type UnknownLoginMethod = {
    loginMethod: 'unknown'
}

export type LoginMethod =
    | PasswordLoginMethod
    | MagicLinkLoginMethod
    | SocialSsoLoginMethod
    | EmailConfirmationLinkLoginMethod
    | SamlSsoLoginMethod
    | ImpersonationLoginMethod
    | GeneratedFromBackendApiLoginMethod
    | UnknownLoginMethod

export function toLoginMethod(snake_case?: InternalLoginMethod): LoginMethod {
    if (!snake_case) {
        return { loginMethod: 'unknown' }
    }

    switch (snake_case.login_method) {
        case 'password':
            return { loginMethod: 'password' }
        case 'magic_link':
            return { loginMethod: 'magic_link' }
        case 'social_sso':
            return { loginMethod: 'social_sso', provider: snake_case.provider }
        case 'email_confirmation_link':
            return { loginMethod: 'email_confirmation_link' }
        case 'saml_sso':
            return { loginMethod: 'saml_sso', provider: snake_case.provider, orgId: snake_case.org_id }
        case 'impersonation':
            return { loginMethod: 'impersonation' }
        case 'generated_from_backend_api':
            return { loginMethod: 'generated_from_backend_api' }
        default:
            return { loginMethod: 'unknown' }
    }
}
