import { useContext } from 'react'
import { AuthContext } from './AuthProvider'

export function useHostedPageUrls() {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error('useHostedPageUrls must be used within an AuthProvider')
    }
    const {
        getLoginPageUrl,
        getSignupPageUrl,
        getAccountPageUrl,
        getOrgPageUrl,
        getOrgSettingsPageUrl,
        getCreateOrgPageUrl,
        getSetupSAMLPageUrl,
    } = context
    return {
        getLoginPageUrl,
        getSignupPageUrl,
        getAccountPageUrl,
        getOrgPageUrl,
        getOrgSettingsPageUrl,
        getCreateOrgPageUrl,
        getSetupSAMLPageUrl,
    }
}
