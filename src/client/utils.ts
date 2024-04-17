import { UserFromToken } from '../user'
import { User } from './useUser'

export const USER_INFO_KEY = '__PROPEL_AUTH_USER_INFO'

export function hasWindow(): boolean {
    return typeof window !== 'undefined'
}

export function saveUserToLocalStorage(user: User | undefined) {
    if (user) {
        localStorage.setItem(USER_INFO_KEY, JSON.stringify(user))
    } else {
        localStorage.setItem(USER_INFO_KEY, '{}')
    }
}

export function doesLocalStorageMatch(newValue: string | null, user: UserFromToken | undefined): boolean {
    if (!newValue) {
        return false
    } else if (!user) {
        return newValue === '{}'
    }

    const parsed = JSON.parse(newValue)
    if (!parsed) {
        return false
    }

    return isEqual(parsed, user)
}

export function isEqual(a: any, b: any): boolean {
    if (typeof a !== typeof b) {
        return false
    } else if (a === null || b === null) {
        return a === b
    }

    if (Array.isArray(a) !== Array.isArray(b)) {
        return false
    }

    if (Array.isArray(a)) {
        const aArray = a as any[]
        const bArray = b as any[]
        if (aArray.length !== bArray.length) {
            return false
        }

        for (let i = 0; i < aArray.length; i++) {
            if (!isEqual(aArray[i], bArray[i])) {
                return false
            }
        }

        return true
    }

    if (typeof a === 'object') {
        const aKeys = Object.keys(a)
        const bKeys = Object.keys(b)
        if (aKeys.length !== bKeys.length) {
            return false
        }

        for (const key of aKeys) {
            if (!isEqual(a[key], b[key])) {
                return false
            }
        }

        return true
    } else {
        return a === b
    }
}
