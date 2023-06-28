import {getApis} from "@propelauth/node-apis";
import {getAuthUrl, getIntegrationApiKey} from "./shared";

export const getPropelAuthApis = () => {
    const authUrl = getAuthUrl()
    const integrationApiKey = getIntegrationApiKey()

    return getApis(authUrl, integrationApiKey)
}