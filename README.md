## PropelAuth Next.js (v13 / AppRouter) Library

[PropelAuth](https://www.propelauth.com?utm_source=github&utm_medium=library&utm_campaign=nextjs) is a user management and authentication service for your B2B/multi-tenant applications.

This library provides a simple way to integrate your Next.js application with PropelAuth. 

### Installation

```bash
npm install @propelauth/nextjs
```

### Setup

Before you start, make sure you have a PropelAuth account. You can sign up for free at [here](https://auth.propelauth.com).

Create a file called `propelauth.ts` in the `src` directory (or your project's root if you prefer) with the following content:

```typescript
import {initializeAuth} from "@propelauth/nextjs/server";

const auth = initializeAuth({
    authUrl: process.env.NEXT_PUBLIC_AUTH_URL,
    redirectUri: process.env.REDIRECT_URI,
    integrationApiKey: process.env.INTEGRATION_API_KEY,
    verifierKey: process.env.VERIFIER_KEY,
})

export const {
    getRouteHandler,
    postRouteHandler,
    getUser,
    getUserOrRedirect,
    validateAccessToken,
    validateAccessTokenOrUndefined,
    authMiddleware,
} = auth
```

This file exports all of our server-side functions that you will need to use in your application. 
You can find all the env variables for your application in the PropelAuth Dashboard under **Backend Integration**.

#### 1. Set up middleware

In your `src/middleware.ts` file, add the following:

```typescript
import {authMiddleware} from "@/auth";

export const middleware = authMiddleware

// The middleware is responsible for keeping the user session up to date.
// It should be called on every request that requires authentication AND /api/auth/.* routes.
export const config = {
    matcher: [
        // REQUIRED: Match all request paths that start with /api/auth/
        '/api/auth/(.*)',
        // OPTIONAL: Don't match any static assets
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
}
```

#### 2. Set up routes (AppRouter)

In your `src/app/api/auth/[slug]` directory, create a file called `route.ts` with the following content:

```typescript
import {getRouteHandler, postRouteHandler} from "@/auth";

export const GET = getRouteHandler
export const POST = postRouteHandler
```

#### 3. Set up AuthProvider (AppRouter)

In your root layout, `src/app/layout.tsx`, add the `AuthProvider`:

```typescript jsx
export default async function RootLayout({children}: {children: React.ReactNode}) {
    return (
        <html lang="en">
        <AuthProvider authUrl={process.env.NEXT_PUBLIC_AUTH_URL}>
            <body className={inter.className}>{children}</body>
        </AuthProvider>
        </html>
    )
}
```

### Usage

#### Get the user in Server Components

```tsx
import {getUser} from "@/auth";

const WelcomeMessage = () => {
    const user = getUser()
    
    if (user) {
        return <div>Hello {user.firstName}!</div>
    } else {
        return <div>Please log in to be welcomed</div>
    }
}
```

```tsx
import {getUserOrRedirect} from "@/auth";

const WelcomeMessage = () => {
    // If the user is not logged in, they will be redirected to the login page
    const user = getUserOrRedirect()
    
    return <div>Hello {user.firstName}!</div>
}
```

#### Get the user in Client Components

```tsx
"use client";

import {useUser} from "@propelauth/nextjs/client";

const WelcomeMessage = () => {
    const {loading, user} = useUser()
   
    if (loading) {
        return <div>Loading...</div>
    } else if (user) {
        return <div>Hello {user.firstName}!</div>
    } else {
        return <div>Please log in to be welcomed</div>
    }
}
```

#### Checking organization membership / RBAC

Note that this works on both the client and server's `User` object, but the below example is on the server.

If you are curious where the organization information comes from, check out our documentation on [organizations](https://docs.propelauth.com/overview/organizations?utm_source=github&utm_medium=library&utm_campaign=nextjs).
The quick answer is:
- PropelAuth provides UI for users to create organizations and invite other users to join them.
- Your users can also create Enterprise SSO/SAML connections to their own Identity Providers (IdPs) so their organization members can log in with their existing work credentials.
- You can create organizations and add users to them via our APIs or our Dashboard.

```tsx
// src/app/org/[slug]/page.tsx
import {getUserOrRedirect} from "@/auth";

export default async function AdminOnlyPage({ params }: { params: { slug: string } }) {
    const user = await getUserOrRedirect()
    const org = user.getOrgByName(params.slug);
    const isAdmin = org?.isRole("Admin")

    if (!isAdmin) {
        return <div>Not found</div>
    } else {
        return <div>Welcome {user.firstName}, Admin of {org?.orgName}</div>
    }
}
```

#### Logging out

```tsx
"use client"

import {useLogoutFunction} from "@propelauth/nextjs/client";

export default function LogoutButton() {
    const logoutFn = useLogoutFunction()
    return <button onClick={logoutFn}>Logout</button>
}
```

#### Logging in / Signing up

If you don't want to use redirect functions, you can also use `useHostedPageUrls` which will return the URLs instead of redirecting.

```tsx
"use client"

import {useRedirectFunctions} from "@propelauth/nextjs/client";

export default function SignupAndLoginButtons() {
    const {redirectToSignupPage, redirectToLoginPage} = useRedirectFunctions()
    return <>
        <button onClick={redirectToSignupPage}>Sign up</button>
        <button onClick={redirectToLoginPage}>Log in</button>
    </>
}
```

#### Redirecting to Account / Org pages

PropelAuth also provides you with pre-built account and organization management UIs. 
You can redirect your users to these pages by using the following functions:

```tsx
"use client"

import {useRedirectFunctions} from "@propelauth/nextjs/client";

export default function AccountAndOrgButtons() {
    const {redirectToAccountPage, redirectToOrgPage} = useRedirectFunctions()
    return <>
        <button onClick={redirectToAccountPage}>Account</button>
        <button onClick={redirectToOrgPage}>Organization</button>
    </>
}
```