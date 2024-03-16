function coerceToArrayBuffer(thing, name) {
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
}

function coerceToBase64Url(thing) {
    // Array or ArrayBuffer to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }

    if (thing instanceof ArrayBuffer) {
        thing = new Uint8Array(thing);
    }

    // Uint8Array to base64
    if (thing instanceof Uint8Array) {
        var str = "";
        var len = thing.byteLength;

        for (var i = 0; i < len; i++) {
            str += String.fromCharCode(thing[i]);
        }
        thing = window.btoa(str);
    }

    if (typeof thing !== "string") {
        throw new Error("could not coerce to string");
    }

    // base64 to base64url
    // NOTE: "=" at the end of challenge is optional, strip it off here
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
}

function authenticate(session, options) {
    options.challenge = coerceToArrayBuffer(options.challenge);
    options.allowCredentials = options.allowCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });
    navigator.credentials.get({ publicKey: options }).then(credential => {
        let authData = new Uint8Array(credential.response.authenticatorData);
        let clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
        let rawId = new Uint8Array(credential.rawId);
        let sig = new Uint8Array(credential.response.signature);
        let clientResponse = JSON.stringify({
            id: credential.id,
            rawId: coerceToBase64Url(rawId),
            type: credential.type,
            extensions: credential.getClientExtensionResults(),
            response: {
                authenticatorData: coerceToBase64Url(authData),
                clientDataJSON: coerceToBase64Url(clientDataJSON),
                signature: coerceToBase64Url(sig)
            }
        });
        let form = document.createElement("form");
        form.style = "display: none;";
        form.method = "POST";
        form.action = "/authorize";
        let sessionInput = document.createElement("input");
        sessionInput.name = "session";
        sessionInput.value = session;
        let clientResponseInput = document.createElement("input");
        clientResponseInput.name = "response";
        clientResponseInput.value = clientResponse;
        form.appendChild(sessionInput);
        form.appendChild(clientResponseInput);
        document.body.appendChild(form);
        form.submit();
    }).catch(e => {
        console.log(e);
        alert("Something went wrong: " + e);
    });
}
