/*
    Auth Handler @mstd.me
*/

import { Router } from 'itty-router';

import {
    ChangePasswordCommand,
    CognitoIdentityProviderClient,
    ConfirmForgotPasswordCommand,
    ConfirmSignUpCommand,
    ForgotPasswordCommand,
    InitiateAuthCommand,
    ResendConfirmationCodeCommand,
    SignUpCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { CognitoJwtVerifier } from "aws-jwt-verify";


const AWSRegion = REGION
const AWSClientId = CLIENT_ID
const AWSClientSecret = CLIENT_SECRET
const AWSUserPoolId = USER_POOL_ID


const router = Router()
const awsClient = new CognitoIdentityProviderClient({ region: AWSRegion });
const awsCognitoJWTVerifier = CognitoJwtVerifier.create(
    { userPoolId: AWSUserPoolId, tokenUse: "access", clientId: AWSClientId });


async function createHmacSignature(username) {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(AWSClientSecret),
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(username + AWSClientId)
    );
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
};


async function handleResponse(data, statusCode) {
    return new Response(
        JSON.stringify(data, { status: statusCode })
    )
}


async function SignUpHandler(request, env, ctx) {
    const { email, password, username } = await request.json();
    try {
        const signature = await createHmacSignature(username);
        const command = new SignUpCommand({
            ClientId: AWSClientId,
            SecretHash: signature,
            Password: password,
            Username: username,
            UserAttributes: [
                {
                    "Name": "email",
                    "Value": email
                }
            ]
        });
        const response = await awsClient.send(command);
        return await handleResponse({ data: response }, 201)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
}


async function SignupConfirmHandler(request, env, ctx) {
    const { username, code } = await request.json();
    try {
        const signature = await createHmacSignature(username);
        const command = new ConfirmSignUpCommand({
            ClientId: AWSClientId,
            SecretHash: signature,
            Username: username,
            ConfirmationCode: new String(code)
        });
        const response = await awsClient.send(command);

        await KV_SESSIONS.put(username, `${username} saved`);

        if (await KV_SESSIONS.get(username)) {
            console.log("saved!");
        } else {
            console.log("NOT SAVED!");
        }

        return await handleResponse({ data: response }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
}


async function SignupResendCodeHandler(request, env, ctx) {
    const { email } = await request.json();
    try {
        const signature = await createHmacSignature(email);
        const command = new ResendConfirmationCodeCommand({
            ClientId: AWSClientId,
            SecretHash: signature,
            Username: email,
        });
        const response = await awsClient.send(command);
        return await handleResponse({ data: response }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
}


async function SignInHandler(request, env, ctx) {
    const { email, username, password } = await request.json();
    try {
        const signature = await createHmacSignature(username);
        const command = new InitiateAuthCommand({
            ClientId: AWSClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": signature,
            }
        });
        const response = await awsClient.send(command);
        return await handleResponse({ data: response.AuthenticationResult }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
}


async function refreshTokenHandler(request, env, ctx) {
    const { accessToken, refreshToken } = await request.json();
    try {
        const [header, encodedPayload, sign] = accessToken.split(".")
        const payloadObject = JSON.parse(atob(encodedPayload))

        const signature = await createHmacSignature(payloadObject.username);
        const command = new InitiateAuthCommand({
            ClientId: AWSClientId,
            AuthFlow: "REFRESH_TOKEN_AUTH",
            AuthParameters: {
                "SECRET_HASH": signature,
                "REFRESH_TOKEN": refreshToken,
            }
        });
        const response = await awsClient.send(command);
        return await handleResponse({ data: response }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
};


async function forgotPasswordHandler(request, env, ctx) {
    const { email } = await request.json();
    try {
        const signature = await createHmacSignature(email);
        const command = new ForgotPasswordCommand({
            ClientId: AWSClientId,
            SecretHash: signature,
            Username: email,
        });
        const response = await awsClient.send(command);
        return await handleResponse({ data: response }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
};


async function forgotPasswordConfirmHandler(request, env, ctx) {
    const { email, password, confirmationCode } = await request.json();
    try {
        const signature = await createHmacSignature(email);
        const command = new ConfirmForgotPasswordCommand({
            ClientId: AWSClientId,
            SecretHash: signature,
            Username: email,
            Password: password,
            ConfirmationCode: confirmationCode,
        }); 
        const response = await awsClient.send(command);
        return await handleResponse({ data: response }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
};


async function changePasswordHandler(request, env, ctx) {
    const { token, previousPassword, proposedPassword } = await request.json();
    try {
        const command = new ChangePasswordCommand({
            AccessToken: token,
            PreviousPassword: previousPassword,
            ProposedPassword: proposedPassword,
        });
        const response = await awsClient.send(command);
        return await handleResponse({ data: response }, 200)
    } catch (error) {
        return await handleResponse({ error: error.message }, 400)
    }
};


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


async function getUsernameHandler(request, env, ctx) {
    try {
        const username = await KV_USERNAMES.get(request.params.username);
        return await handleResponse({ data: username }, 200);
    } catch (error) {
        return await handleResponse({ error: error.message }, 400);
    }
}


async function createUsernameHandler(request, env, ctx) {
    const { username } = await request.json();
    try {
        const put_response = await KV_USERNAMES.put(username, "the-value");
        console.log(">>", put_response)

        const get_response = await KV_USERNAMES.get(username);
        console.log(get_response);

        return await handleResponse({ data: get_response }, 201);
    } catch (error) {
        return await handleResponse({ error: error.message }, 400);
    }
}


router
    .post('/signup', SignUpHandler)
    .post('/signup/confirm', SignupConfirmHandler)
    .post('/signup/resend_code', SignupResendCodeHandler)
    .post('/signin', SignInHandler)
    .post('/refresh_token', refreshTokenHandler)
    .post('/forgot_password', forgotPasswordHandler)
    .post('/forgot_password/confirm', forgotPasswordConfirmHandler)
    .post('/change_password', changePasswordHandler)

    .get('/username/:username', getUsernameHandler)
    .post('/username', loginRequired, createUsernameHandler)

    .all('*', () => new Response('Not Found.', { status: 404 }))

    


addEventListener('fetch', event =>
    event.respondWith(router.handle(event.request, event.env, event.context))
)
