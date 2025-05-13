import { useContext } from 'react'
import { AuthContext } from './AuthProvider'

export function useAuthUrl() {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error('useAuthUrl must be used within an AuthProvider')
    }
    const { authUrl } = context
    return authUrl
}
