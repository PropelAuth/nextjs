import {User} from "./user";

export type LoggedInProps = {
    loading: false
    isLoggedIn: true
    user: User
}

export type LoggedOutProps = {
    loading: false
    isLoggedIn: false
    user: undefined
}