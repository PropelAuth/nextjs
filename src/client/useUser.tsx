'use client'

import {useContext} from "react"
import {AuthContext} from "./AuthProvider"
import {OrgIdToOrgMemberInfo, OrgMemberInfo} from "../user";

export class User {
    public userId: string
    public email: string
    public emailConfirmed: boolean
    public hasPassword: boolean

    public username?: string
    public firstName?: string
    public lastName?: string
    public pictureUrl?: string

    public orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo

    public mfaEnabled: boolean
    public canCreateOrgs: boolean
    public updatePasswordRequired: boolean

    public createdAt: number
    public lastActiveAt: number

    public properties?: {[key: string]: unknown}

    public legacyUserId?: string
    public impersonatorUserId?: string

    constructor({
                    userId,
                    email,
                    emailConfirmed,
                    hasPassword,
                    username,
                    firstName,
                    lastName,
                    pictureUrl,
                    orgIdToOrgMemberInfo,
                    mfaEnabled,
                    canCreateOrgs,
                    updatePasswordRequired,
                    createdAt,
                    lastActiveAt,
                    legacyUserId,
                    properties,
                    impersonatorUserId,
                }: {
        userId: string
        email: string
        emailConfirmed: boolean
        hasPassword: boolean
        username?: string
        firstName?: string
        lastName?: string
        pictureUrl?: string
        orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo
        mfaEnabled: boolean
        canCreateOrgs: boolean
        updatePasswordRequired: boolean
        createdAt: number
        lastActiveAt: number
        legacyUserId?: string
        properties?: {[key: string]: unknown}
        impersonatorUserId?: string
    }) {
        this.userId = userId
        this.email = email
        this.emailConfirmed = emailConfirmed
        this.hasPassword = hasPassword
        this.username = username
        this.firstName = firstName
        this.lastName = lastName
        this.pictureUrl = pictureUrl
        this.orgIdToOrgMemberInfo = orgIdToOrgMemberInfo
        this.mfaEnabled = mfaEnabled
        this.canCreateOrgs = canCreateOrgs
        this.updatePasswordRequired = updatePasswordRequired
        this.createdAt = createdAt
        this.lastActiveAt = lastActiveAt
        this.legacyUserId = legacyUserId
        this.properties = properties
        this.impersonatorUserId = impersonatorUserId
    }

    public getOrg(orgId: string): OrgMemberInfo | undefined {
        return this.orgIdToOrgMemberInfo?.[orgId]
    }

    public getOrgByName(orgName: string): OrgMemberInfo | undefined {
        if (!this.orgIdToOrgMemberInfo) {
            return undefined
        }

        const urlSafeOrgName = orgName.toLowerCase().replace(/ /g, "-")
        for (const orgId in this.orgIdToOrgMemberInfo) {
            const orgMemberInfo = this.orgIdToOrgMemberInfo[orgId]
            if (orgMemberInfo.urlSafeOrgName === urlSafeOrgName) {
                return orgMemberInfo
            }
        }

        return undefined
    }

    public getOrgs(): OrgMemberInfo[] {
        if (!this.orgIdToOrgMemberInfo) {
            return []
        }

        return Object.values(this.orgIdToOrgMemberInfo)
    }

    public isImpersonating(): boolean {
        return !!this.impersonatorUserId
    }
}

export type UseUserLoading = {
    loading: true
    isLoggedIn: never
    user: never
    accessToken: never
}

export type UseUserLoggedIn = {
    loading: false
    isLoggedIn: true
    user: User
    accessToken: string
}

export type UseUserNotLoggedIn = {
    loading: false
    isLoggedIn: false
    user: undefined
    accessToken: undefined
}

export type UseUser = UseUserLoading | UseUserLoggedIn | UseUserNotLoggedIn

export function useUser(): UseUser {
    const context = useContext(AuthContext)
    if (context === undefined) {
        throw new Error("useUser must be used within an AuthProvider")
    }

    const {loading, userAndAccessToken} = context
    if (loading) {
        return {
            loading: true,
            isLoggedIn: undefined as never,
            user: undefined as never,
            accessToken: undefined as never,
        }
    } else if (userAndAccessToken.user) {
        return {
            loading: false,
            isLoggedIn: true,
            user: userAndAccessToken.user,
            accessToken: userAndAccessToken.accessToken,
        }
    } else {
        return {
            loading: false,
            isLoggedIn: false,
            user: undefined,
            accessToken: undefined,
        }
    }
}