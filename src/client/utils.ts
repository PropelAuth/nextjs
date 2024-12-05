export function hasWindow(): boolean {
    return typeof window !== 'undefined'
}

export const currentTimeSecs = (): number => {
    return Math.floor(Date.now() / 1000)
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
