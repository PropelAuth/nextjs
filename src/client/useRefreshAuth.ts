import { useContext } from "react"
import { AuthContext } from "./AuthProvider"

export function useRefreshAuth() {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error("useRefreshAuth must be used within an AuthProvider")
    }
    const { refreshAuthInfo } = context
    return refreshAuthInfo
}
