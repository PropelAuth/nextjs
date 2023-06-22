# PropelAuth Next.js (v13+) Library

[PropelAuth](https://www.propelauth.com?utm_source=github&utm_medium=library&utm_campaign=nextjs) is a user management and authentication service for your B2B/multi-tenant applications.

This library provides a simple way to integrate your Next.js application (either AppRouter or Pages) with PropelAuth.

Next.js SSR/AppRouter support is in beta, while in beta, you'll need to reach out to support@propelauth.com to have this enabled for your account. 

## Installation

```bash
npm install @propelauth/nextjs
```

## Setup

Before you start, make sure you have a PropelAuth account. You can sign up for free at [here](https://auth.propelauth.com).

You'll need to set the following .env variables in your Next.js application:

- NEXT_PUBLIC_AUTH_URL
- PROPELAUTH_API_KEY
- PROPELAUTH_VERIFIER_KEY
- PROPELAUTH_REDIRECT_URI

You can find the env variables for your application in the PropelAuth Dashboard under **Backend Integration**.
For the PROPELAUTH_REDIRECT_URI, you should use `{YOUR_URL}/api/auth/callback`. 
For example, if your application is hosted at `https://myapp.com`, then your PROPELAUTH_REDIRECT_URI would be `https://myapp.com/api/auth/callback`.
Make sure to set this in the **Frontend Integration** section of your dashboard.

### 1. Set up routes

In your `src/app/api/auth/[slug]` directory, create a file called `route.ts` with the following content:

```typescript
import {getRouteHandlers} from "@propelauth/nextjs/server/app-router";
import {User} from "@propelauth/nextjs/server";
import {NextRequest} from "next/server";

// postLoginRedirectPathFn is optional, but if you want to redirect the user to a different page after login, you can do so here.
const routeHandlers = getRouteHandlers({
    postLoginRedirectPathFn: (req: NextRequest) => {
        return "/"
    }
})
export const GET = routeHandlers.getRouteHandler
export const POST = routeHandlers.postRouteHandler
```

### 2. Set up AuthProvider 

#### AppRouter Version

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

#### Pages Version

In your `_app.tsx` file, add the `AuthProvider`:

```typescript jsx
export default function MyApp({Component, pageProps}: AppProps) {
    return (
        <AuthProvider authUrl={process.env.NEXT_PUBLIC_AUTH_URL}>
            <Component {...pageProps} />
        </AuthProvider>
    )
}
```

### 3. Set up middleware (AppRouter only - skip if using Pages)

In your `src/middleware.ts` file, add the following:

```typescript
import {authMiddleware} from "@propelauth/nextjs/server/app-router";

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

## Usage

### Get the user in Server Components (AppRouter example)

```tsx
import {getUser} from "@propelauth/nextjs/server/app-router";

const WelcomeMessage = async () => {
    const user = await getUser()
    
    if (user) {
        return <div>Hello {user.firstName}!</div>
    } else {
        return <div>Please log in to be welcomed</div>
    }
}
```

```tsx
import {getUser} from "@propelauth/nextjs/server/app-router";

const WelcomeMessage = async () => {
    // If the user is not logged in, they will be redirected to the login page
    const user = await getUserOrRedirect()
    
    return <div>Hello {user.firstName}!</div>
}
```

### Get the user in getServerSideProps (Pages example)

```tsx
import {GetServerSideProps, InferGetServerSidePropsType} from "next";
import {getUserFromServerSideProps} from "@propelauth/nextjs/server/pages";
import {User} from "@propelauth/nextjs/client";

export default function WelcomeMessage({userJson}: InferGetServerSidePropsType<typeof getServerSideProps>) {
    // Deserialize the user from the JSON string so you can call functions like user.getOrg()
    const user = User.fromJSON(userJson)
    return <div>Hello, {user.firstName}</div>
}

export const getServerSideProps: GetServerSideProps = async (context) => {
    const user = await getUserFromServerSideProps(context)
    if (!user) {
        return {redirect: {destination: '/api/auth/login', permanent: false}}
    }
    return { props: {userJson: JSON.stringify(user) } }
}
```


### Get the user in Client Components

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

### Checking organization membership / RBAC

Note that this works on both the client and server's `User` object, but the below example is on the server.

If you are curious where the organization information comes from, check out our documentation on [organizations](https://docs.propelauth.com/overview/organizations?utm_source=github&utm_medium=library&utm_campaign=nextjs).
The quick answer is:
- PropelAuth provides UI for users to create organizations and invite other users to join them.
- Your users can also create Enterprise SSO/SAML connections to their own Identity Providers (IdPs) so their organization members can log in with their existing work credentials.
- You can create organizations and add users to them via our APIs or our Dashboard.

```tsx
// src/app/org/[slug]/page.tsx
import {getUserOrRedirect} from "@propelauth/nextjs/server/app-router";

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

### Logging out

```tsx
"use client"

import {useLogoutFunction} from "@propelauth/nextjs/client";

export default function LogoutButton() {
    const logoutFn = useLogoutFunction()
    return <button onClick={logoutFn}>Logout</button>
}
```

### Logging in / Signing up

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

### Redirecting to Account / Org pages

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
