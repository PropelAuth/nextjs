import { InternalLoginMethod, LoginMethod, toLoginMethod } from './loginMethod'

export class UserFromToken {
    public userId: string

    public activeOrgId?: string
    public orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo

    // Metadata about the user
    public email: string
    public firstName?: string
    public lastName?: string
    public username?: string
    public pictureUrl?: string
    public properties?: { [key: string]: unknown }
    public loginMethod?: LoginMethod

    // If you used our migration APIs to migrate this user from a different system,
    //   this is their original ID from that system.
    public legacyUserId?: string
    public impersonatorUserId?: string

    constructor(
        userId: string,
        email: string,
        orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo,
        firstName?: string,
        lastName?: string,
        username?: string,
        legacyUserId?: string,
        impersonatorUserId?: string,
        properties?: { [key: string]: unknown },
        pictureUrl?: string
        activeOrgId?: string,
        loginMethod?: LoginMethod
    ) {
        this.userId = userId

        this.activeOrgId = activeOrgId
        this.orgIdToOrgMemberInfo = orgIdToOrgMemberInfo

        this.email = email
        this.firstName = firstName
        this.lastName = lastName
        this.username = username

        this.legacyUserId = legacyUserId
        this.impersonatorUserId = impersonatorUserId

        this.properties = properties
        this.pictureUrl = pictureUrl
        this.loginMethod = loginMethod
    }

    public getActiveOrg(): OrgMemberInfo | undefined {
        if (!this.activeOrgId || !this.orgIdToOrgMemberInfo) {
            return undefined
        }

        return this.orgIdToOrgMemberInfo[this.activeOrgId]
    }

    public getActiveOrgId(): string | undefined {
        return this.activeOrgId
    }

    public getOrg(orgId: string): OrgMemberInfo | undefined {
        if (!this.orgIdToOrgMemberInfo) {
            return undefined
        }

        return this.orgIdToOrgMemberInfo[orgId]
    }

    public getOrgByName(orgName: string): OrgMemberInfo | undefined {
        if (!this.orgIdToOrgMemberInfo) {
            return undefined
        }

        const urlSafeOrgName = orgName.toLowerCase().replace(/ /g, '-')
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

    public static fromJSON(json: string): UserFromToken {
        const obj = JSON.parse(json)
        const orgIdToOrgMemberInfo: OrgIdToOrgMemberInfo = {}
        for (const orgId in obj.orgIdToOrgMemberInfo) {
            orgIdToOrgMemberInfo[orgId] = OrgMemberInfo.fromJSON(JSON.stringify(obj.orgIdToOrgMemberInfo[orgId]))
        }
        return new UserFromToken(
            obj.userId,
            obj.email,
            orgIdToOrgMemberInfo,
            obj.firstName,
            obj.lastName,
            obj.username,
            obj.legacyUserId,
            obj.impersonatorUserId,
            obj.properties,
            obj.pictureUrl,
            obj.activeOrgId,
            obj.loginMethod
        )
    }

    public static fromJwtPayload(payload: InternalUser): UserFromToken {
        let activeOrgId: string | undefined
        let orgIdToOrgMemberInfo: OrgIdToOrgMemberInfo | undefined

        if (payload.org_member_info) {
            activeOrgId = payload.org_member_info.org_id
            orgIdToOrgMemberInfo = toOrgIdToOrgMemberInfo({ [activeOrgId]: payload.org_member_info })
        } else {
            activeOrgId = undefined
            orgIdToOrgMemberInfo = toOrgIdToOrgMemberInfo(payload.org_id_to_org_member_info)
        }

        const loginMethod = toLoginMethod(payload.login_method)

        return new UserFromToken(
            payload.user_id,
            payload.email,
            orgIdToOrgMemberInfo,
            payload.first_name,
            payload.last_name,
            payload.username,
            payload.legacy_user_id,
            payload.impersonator_user_id,
            payload.properties,
            activeOrgId,
            loginMethod
        )
    }
}

export type OrgIdToOrgMemberInfo = {
    [orgId: string]: OrgMemberInfo
}

export enum OrgRoleStructure {
    SingleRole = "single_role_in_hierarchy",
    MultiRole = "multi_role",
}

export class OrgMemberInfo {
    public orgId: string
    public orgName: string
    public orgMetadata: { [key: string]: any }
    public urlSafeOrgName: string
    public orgRoleStructure: OrgRoleStructure

    public userAssignedRole: string
    public userInheritedRolesPlusCurrentRole: string[]
    public userPermissions: string[]
    public userAssignedAdditionalRoles: string[]

    constructor(
        orgId: string,
        orgName: string,
        orgMetadata: { [key: string]: any },
        urlSafeOrgName: string,
        userAssignedRole: string,
        userInheritedRolesPlusCurrentRole: string[],
        userPermissions: string[],
        orgRoleStructure: OrgRoleStructure,
        userAssignedAdditionalRoles: string[]
    ) {
        this.orgId = orgId
        this.orgName = orgName
        this.orgMetadata = orgMetadata
        this.urlSafeOrgName = urlSafeOrgName
        this.orgRoleStructure = orgRoleStructure

        this.userAssignedRole = userAssignedRole
        this.userInheritedRolesPlusCurrentRole = userInheritedRolesPlusCurrentRole
        this.userPermissions = userPermissions
        this.userAssignedAdditionalRoles = userAssignedAdditionalRoles
    }

    // validation methods

    public isRole(role: string): boolean {
        if (this.orgRoleStructure === OrgRoleStructure.MultiRole) {
            return this.userAssignedRole === role || this.userAssignedAdditionalRoles.includes(role)
        } else {
            return this.userAssignedRole === role
        }
    }

    public isAtLeastRole(role: string): boolean {
        if (this.orgRoleStructure === OrgRoleStructure.MultiRole) {
            return this.userAssignedRole === role || this.userAssignedAdditionalRoles.includes(role)
        } else {
            return this.userInheritedRolesPlusCurrentRole.includes(role)
        }
    }

    public hasPermission(permission: string): boolean {
        return this.userPermissions.includes(permission)
    }

    public hasAllPermissions(permissions: string[]): boolean {
        return permissions.every((permission) => this.hasPermission(permission))
    }

    public static fromJSON(json: string): OrgMemberInfo {
        const obj = JSON.parse(json)
        return new OrgMemberInfo(
            obj.orgId,
            obj.orgName,
            obj.orgMetadata,
            obj.urlSafeOrgName,
            obj.userAssignedRole,
            obj.userInheritedRolesPlusCurrentRole,
            obj.userPermissions,
            obj.orgRoleStructure,
            obj.userAssignedAdditionalRoles
        )
    }

    // getters for the private fields

    get assignedRole(): string {
        return this.userAssignedRole
    }

    get assignedRoles(): string[] {
        if (this.orgRoleStructure === OrgRoleStructure.MultiRole) {
            return this.userAssignedAdditionalRoles.concat(this.userAssignedRole)
        } else {
            return [this.userAssignedRole]
        }
    }

    get inheritedRolesPlusCurrentRole(): string[] {
        if (this.orgRoleStructure === OrgRoleStructure.MultiRole) {
            return this.userAssignedAdditionalRoles.concat(this.userAssignedRole)
        } else {
            return this.userInheritedRolesPlusCurrentRole
        }
    }

    get permissions(): string[] {
        return this.userPermissions
    }
}

// These Internal types exist since the server returns snake case, but typescript/javascript
// convention is camelCase.
export type InternalOrgMemberInfo = {
    org_id: string
    org_name: string
    org_metadata: { [key: string]: any }
    url_safe_org_name: string
    org_role_structure: OrgRoleStructure
    user_role: string
    inherited_user_roles_plus_current_role: string[]
    user_permissions: string[]
    additional_roles: string[]
}

export type InternalUser = {
    user_id: string

    org_member_info?: InternalOrgMemberInfo
    org_id_to_org_member_info?: { [org_id: string]: InternalOrgMemberInfo }

    email: string
    first_name?: string
    last_name?: string
    username?: string
    picture_url?: string
    properties?: { [key: string]: unknown }
    login_method?: InternalLoginMethod

    // If you used our migration APIs to migrate this user from a different system, this is their original ID from that system.
    legacy_user_id?: string
    impersonator_user_id?: string
}

export function toUser(snake_case: InternalUser): UserFromToken {
    return UserFromToken.fromJwtPayload(snake_case)
}

export function toOrgIdToOrgMemberInfo(snake_case?: {
    [org_id: string]: InternalOrgMemberInfo
}): OrgIdToOrgMemberInfo | undefined {
    if (snake_case === undefined) {
        return undefined
    }
    const camelCase: OrgIdToOrgMemberInfo = {}

    for (const key of Object.keys(snake_case)) {
        const snakeCaseValue = snake_case[key]
        if (snakeCaseValue) {
            camelCase[key] = new OrgMemberInfo(
                snakeCaseValue.org_id,
                snakeCaseValue.org_name,
                snakeCaseValue.org_metadata,
                snakeCaseValue.url_safe_org_name,
                snakeCaseValue.user_role,
                snakeCaseValue.inherited_user_roles_plus_current_role,
                snakeCaseValue.user_permissions,
                snakeCaseValue.org_role_structure,
                snakeCaseValue.additional_roles
            )
        }
    }

    return camelCase
}
