<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>


# PropelAuth Next.js (v13+) Library

[PropelAuth](https://www.propelauth.com?utm_source=github&utm_medium=library&utm_campaign=nextjs) is a user management and authentication service for your B2B/multi-tenant applications.

This library provides a simple way to integrate your Next.js application (either App Router or Pages) with PropelAuth.

## Installation

```bash
npm install @propelauth/nextjs
```

## Automatic Installation

If you would prefer a manual installation process instead of an automatic one, check out the installation guides for [App Router](https://docs.propelauth.com/reference/fullstack-apis/nextjsapp/installation-and-setup) and [Pages Router](https://docs.propelauth.com/reference/fullstack-apis/nextjspages/installation-and-setup).

Begin by installing the PropelAuth CLI:

```bash
npm i -g @propelauth/cli
```

## Logging into the PropelAuth CLI

Before we install PropelAuth in your Next.js project we first have to log into the CLI. If you haven't already created an account in PropelAuth, navigate to [auth.propelauth.com](https://auth.propelauth.com/en/signup) to get started.

Once you have an account with PropelAuth, run this command to login to the CLI:

```bash
propelauth login
```

To login you'll be prompted to create and copy/paste a Personal API Key into your terminal.

```
┌  ⚡ PropelAuth Login
│
●  
│  Please visit the following URL to create a personal API key:
│
●  https://auth.propelauth.com/api_keys/personal
│
│
◆  Enter your API key
│  # enter your API key here
└
```

You can create a Personal API Key by navigating to https://auth.propelauth.com/api_keys/personal and clicking **+ New API Key**.


### Selecting a Default Project

Once your API Key is validated the CLI will prompt you to select a default project, if desired. If you select a default project, the CLI will not prompt you to select a project again until you repeat the login process or run the `set-default-project` command.

```
┌ 
◇  ✓ Projects fetched successfully
│
◆  Select a project to use
│  ● Always ask which project to use (You will be prompted for each command)
│  ○ Acme Inc / New Project
└
```

## Installing and Setting up PropelAuth in Next.js

Once you have logged into the CLI it's time to install PropelAuth within your Next.js app! Navigate to your Next.js project directory and run the following command:

```bash
propelauth setup
```

During installation you'll see the following prompts:

```
┌  ⚡ PropelAuth Setup
│
◆  Select your project framework:
│  ○ Next.js (App Router)
│  ● Next.js (Pages Router) (Uses pages/ directory structure)
│
◆  Select a project to use for this command
│  ● Acme Inc / New Project
│
◆  Enter the URL your Next.js app runs on:
│  ↳ http://localhost:3000
│
●  No API key found in environment file
│
◆  Would you like to generate a new Backend Integration API Key for this project?
│  ● yes / ○ no
│
│  Enter a name for the new Backend Integration API Key:
│  ↳ Next.js Integration
│
●  Updates needed for the Frontend Integration settings for your test environment
│  - Login redirect path: / → /api/auth/callback
│  - Logout redirect path: / → /api/auth/logout
│  - Development URL: none → http://localhost:3000
│
◆  Your test environment config needs to be updated, would you like to apply these changes now?
│  ● yes / ○ no
│
◆  Install @propelauth/nextjs now?
│  ● npm install @propelauth/nextjs (detected)
│  ○ yarn add @propelauth/nextjs
│  ○ pnpm install @propelauth/nextjs
│  ○ bun install @propelauth/nextjs
│  ○ Skip installation
│
●  _app.tsx with AuthProvider at /src/pages/_app.tsx differs from what we expected.
│
◆  Overwrite _app.tsx with AuthProvider?
│  ● Yes / ○ No
│
└  PropelAuth has been successfully set up in your Next.js project!
```

Once the CLI has successfully installed PropelAuth within your Next.js project it will also include some example components to help you get started.

### App Router Server Component

```jsx {{ title: "Server Component" }}
import { getUserOrRedirect } from "@propelauth/nextjs/server/app-router";

const WelcomeMessage = async () => {
    const user = await getUserOrRedirect()
    return <div>Welcome, {user.email}!</div>
}

export default WelcomeMessage;
```

### App Router Client Component

```jsx
"use client";

import { useUser } from "@propelauth/nextjs/client";

const WelcomeMessage = () => {
    const {loading, user} = useUser()
    if (loading) {
        return <div>Loading...</div>
    } else if (user) {
        return <div>Welcome, {user.email}!</div>
    } else {
        return <div>Please log in to be welcomed</div>
    }
}

export default WelcomeMessage;
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more. 
See the [API Reference](https://docs.propelauth.com/reference) for more information.

```typescript
import { getPropelAuthApis } from "@propelauth/nextjs/server";

// Can be done in an API route or getServerSideProps
const apis = getPropelAuthApis()
await apis.disableUser(userId)
```

## Questions?

Feel free to reach out at support@propelauth.com

