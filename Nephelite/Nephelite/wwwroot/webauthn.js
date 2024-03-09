coerceToArrayBuffer = function (thing, name) {
    if (typeof thing === "string") {
        // base64url to base64
        thing = thing.replace(/-/g, "+").replace(/_/g, "/");

        // base64 to Uint8Array
        var str = window.atob(thing);
        var bytes = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        thing = bytes;
    }

    // Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = new Uint8Array(thing);
    }

    // Uint8Array to ArrayBuffer
    if (thing instanceof Uint8Array) {
        thing = thing.buffer;
    }

    // error if none of the above worked
    if (!(thing instanceof ArrayBuffer)) {
        throw new TypeError("could not coerce '" + name + "' to ArrayBuffer");
    }

    return thing;
};

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
