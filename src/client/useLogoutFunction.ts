import { useContext } from "react"
import { AuthContext } from "./AuthProvider"

export function useLogoutFunction() {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error("useLogoutFunction must be used within an AuthProvider")
    }
    const { logout } = context
    return logout
}
