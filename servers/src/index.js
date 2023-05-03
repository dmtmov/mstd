/*
    Servers Handler @mstd.me
*/

import { Router } from 'itty-router';
import { CognitoJwtVerifier } from "aws-jwt-verify";


const router = Router()
const awsCognitoJWTVerifier = CognitoJwtVerifier.create({
    userPoolId: USER_POOL_ID,
    clientId: CLIENT_ID,
    tokenUse: "access",
});


async function loginRequired(request, env, ctx) {
    const authorization = request.headers.get("Authorization");
    if (!authorization) {
        return new Response(
            "Not authorized!!11",
            { status: 401, statusText: "Unauthorized" }
        )
    }

    try {
        const [scheme, encoded] = authorization.split(" ");

        if (!encoded || scheme !== "Bearer") {
            return new Response(
                "Auth header not identified!",
                { status: 401, statusText: "Unauthorized" }
            )
        }

        try {
            const payload = await awsCognitoJWTVerifier.verify(encoded);
            request.username = payload.username;
        } catch (error) {
            return new Response(
                error.message,
                { status: 401, statusText: "Unauthorized" }
            )
        }

    } catch (error) {
        return new Response(
            "Auth header is broken!",
            { status: 401, statusText: "Unauthorized" }
        )
    }
};


async function handleResponse(data, status) {
    return new Response(
        JSON.stringify(data, { status: status })
    )
}


async function getServerList(request, env, ctx) {
    try {
        const servers = JSON.parse(await KV_SERVERS.get(request.username));
        return await handleResponse({ data: servers }, 200)
    } catch(error) {
        return handleResponse({ error: error.message }, 400)
    }
};


async function createServer(request, env, ctx) {
    try {
        const value = await request.json()
        await KV_SERVERS.put(request.username, value)
        return await handleResponse({ data: "ok" }, 200)
    } catch(error) {
        return await handleResponse({ error: error.message}, 400)
    }
}


async function deleteServer(request, env, ctx) {
    try {
        console.log(request);
        return await handleResponse({ data: "ok" }, 200)
    } catch(error) {
        return await handleResponse({ error: error.message}, 400)
    }
}


async function getPrimaryServer(request, env, ctx) {
    const primaryServer = await KV_REDIRECTS.get(request.username)
    return await handleResponse({ data: primaryServer }, 200)
}


async function setPrimaryServer(request, env, ctx) {
    const { url } = await request.json()

    if (!url.includes("@")) {
        return await handleResponse(
            { error: "No username found in provided URL" }, 400)
    }
    try {
        const temp_resp = await fetch(url)
        console.log(temp_resp.status)
        if (temp_resp.status !== 200) {
            return await handleResponse(
                { error: "Broken URL provided" }, 400)
        }
    } catch(error) {
        return await handleResponse({ error: error.message }, 400)
    }

    try {
        new URL(url);
        await KV_REDIRECTS.put(request.username, url);
    } catch(error) {
        return await handleResponse({ error: error.message }, 400)
    }
    return await handleResponse({ data: "ok" }, 200)
}


/*
GET     /servers         getServers
DELETE  /servers/:server deleteServer
POST    /servers         createServer

GET     /servers/primary getPrimaryServer
POST    /servers/primary setPrimaryServer

*/
router
    .get('/servers', loginRequired, getServerList)
    .post('/servers', loginRequired, createServer)
    .delete('/servers/:server', loginRequired, deleteServer)

    .get('/servers/primary', loginRequired, getPrimaryServer)
    .post('/servers/primary', loginRequired, setPrimaryServer)

    .all('*', () => new Response('Not Found.', { status: 404 }))


addEventListener('fetch', event =>
    event.respondWith(router.handle(event.request, event.env, event.context))
)
