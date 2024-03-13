async function doPost(url, data) {
    let response = await fetch(url, {
        method: "POST",
        body: JSON.stringify(data),
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    });
    return await response.json();
}

async function createCredential() {
    let options = await doPost('/webauthn/registerOptions', {username: "test"});
    options.challenge = coerceToArrayBuffer(options.challenge);
    options.user.id = coerceToArrayBuffer(options.user.id);
    options.excludeCredentials = options.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });
    if (options.authenticatorSelection.authenticatorAttachment === null)
        options.authenticatorSelection.authenticatorAttachment = undefined;

    let credential = await navigator.credentials.create({ publicKey: options });
    let attestationObject = new Uint8Array(credential.response.attestationObject);
    let clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
    let rawId = new Uint8Array(credential.rawId);

    const credentialData = {
        id: credential.id,
        rawId: coerceToBase64Url(rawId),
        type: credential.type,
        response: {
            AttestationObject: coerceToBase64Url(attestationObject),
            clientDataJSON: coerceToBase64Url(clientDataJSON)
        }
    };
    let result = await doPost("/webauthn/register", credentialData);
    console.log(result);
}

async function authenticate() {
    let options = await doPost("/webauthn/authenticationOptions");
    options.challenge = coerceToArrayBuffer(options.challenge);
    options.allowCredentials = options.allowCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });
    let credential = null;
    try {
        credential = await navigator.credentials.get({ publicKey: options });
    } catch (e) {
        console.log("Getting credentials failed");
        console.log(e);
        return;
    }
    let authData = new Uint8Array(credential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
    let rawId = new Uint8Array(credential.rawId);
    let sig = new Uint8Array(credential.response.signature);
    const data = {
        id: credential.id,
        rawId: coerceToBase64Url(rawId),
        type: credential.type,
        extensions: credential.getClientExtensionResults(),
        response: {
            authenticatorData: coerceToBase64Url(authData),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            signature: coerceToBase64Url(sig)
        }
    };
    let result = await doPost("/webauthn/authenticate", data);
    console.log(result);
}
