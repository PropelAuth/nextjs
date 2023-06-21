'use client'

import {useContext} from "react"
import {User} from "../user"
import {AuthContext} from "./AuthProvider"

export type UseUserLoading = {
    loading: true
    isLoggedIn: never
    user: never
}

export type UseUserLoggedIn = {
    loading: false
    isLoggedIn: true
    user: User
}

export type UseUserNotLoggedIn = {
    loading: false
    isLoggedIn: false
    user: undefined
}

export type UseUser = UseUserLoading | UseUserLoggedIn | UseUserNotLoggedIn

export function useUser(): UseUser {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error("useUser must be used within an AuthProvider")
    }

    const {loading, user} = context
    if (loading) {
        return {
            loading: true,
            isLoggedIn: undefined as never,
            user: undefined as never,
        }
    } else if (user) {
        return {
            loading: false,
            isLoggedIn: true,
            user,
        }
    } else {
        return {
            loading: false,
            isLoggedIn: false,
            user: undefined,
        }
    }
}