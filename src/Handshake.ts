/**
 * A four way client-server handshake, as excellently described in https://ssbc.github.io/scuttlebutt-protocol-guide/,
 * with an added arbitrary 96 byte client/server data transmission.
 */

import sodium from "libsodium-wrappers";
import {Client, ByteSize} from "../../pocket-sockets";

import {
    HandshakeResult,
} from "./types";

type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer
};

// Compare two buffers in constant time
function Equals(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
        // Cannot compare buffers of different lengths in constant time
        return false;
    }
    let result = 0;  // == buffers are equal.
    for (let i=0; i<a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;  // true if buffers are equal
}

function createEphemeralKeys(): KeyPair {
    const keyPair = sodium.crypto_box_keypair();
    return {
        publicKey: Buffer.from(keyPair.publicKey),
        secretKey: Buffer.from(keyPair.privateKey)
    };
}

function hmac(msg: Buffer, key: Buffer): Buffer {
    const hmac = sodium.crypto_auth(msg, key);
    return Buffer.from(hmac);
}

function assertHmac(clientHmac: Buffer, msg: Buffer, key: Buffer): boolean {
    const hmac2 = hmac(msg, key);
    return Equals(hmac2, clientHmac);
}

function clientSharedSecret_ab(clientEphemeralSk: Buffer, serverEphemeralPk: Buffer): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(clientEphemeralSk, serverEphemeralPk));
}

function serverSharedSecret_ab(serverEphemeralSk: Buffer, clientEphemeralPk: Buffer): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(serverEphemeralSk, clientEphemeralPk));
}

function clientSharedSecret_aB(clientEphemeralPk: Buffer, serverLongtermPk: Buffer): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(clientEphemeralPk, sodium.crypto_sign_ed25519_pk_to_curve25519(serverLongtermPk)));
}

function serverSharedSecret_aB(serverLongtermSk: Buffer, clientEphemeralPk: Buffer): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(sodium.crypto_sign_ed25519_sk_to_curve25519(serverLongtermSk), clientEphemeralPk));
}

function clientSharedSecret_Ab(clientLongtermSk: Buffer, serverEphemeralPk: Buffer): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(sodium.crypto_sign_ed25519_sk_to_curve25519(clientLongtermSk), serverEphemeralPk));
}

function serverSharedSecret_Ab(serverEphemeralSk: Buffer, clientLongtermPk: Buffer): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(serverEphemeralSk, sodium.crypto_sign_ed25519_pk_to_curve25519(clientLongtermPk)));
}

function signDetached(msg: Buffer, secretKey: Buffer): Buffer {
    return Buffer.from(sodium.crypto_sign_detached(msg, secretKey));
}

function signVerifyDetached(msg: Buffer, sig: Buffer, publicKey: Buffer): boolean {
    return sodium.crypto_sign_verify_detached(sig, msg, publicKey);
}

function secretBox(msg: Buffer, nonce: Buffer, key: Buffer): Buffer {
    return Buffer.from(sodium.crypto_secretbox_easy(msg, nonce, key));
}

function secretBoxOpen(ciphertext: Buffer, nonce: Buffer, key: Buffer): Buffer {
    const unboxed = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
    if (!unboxed) {
        throw "Could not open box";
    }
    return Buffer.from(unboxed);
}

function calcClientToServerKey(discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer, serverLongtermPk: Buffer, serverEphemeralPk: Buffer): [Buffer, Buffer] {
    const inner = hashFn(hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab])));
    const clientToServerKey = hashFn(Buffer.concat([inner, serverLongtermPk]));
    const clientNonce = hmac(serverEphemeralPk, discriminator).slice(0, 24);
    return [clientToServerKey, clientNonce];
}

function calcServerToClientKey(discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer, clientLongtermPk: Buffer, clientEphemeralPk: Buffer): [Buffer, Buffer] {
    const inner = hashFn(hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab])));
    const serverToClientKey = hashFn(Buffer.concat([inner, clientLongtermPk]));
    const serverNonce = hmac(clientEphemeralPk, discriminator).slice(0, 24);
    return [serverToClientKey, serverNonce];
}

function hashFn(message: Buffer): Buffer {
    const digest = sodium.crypto_generichash(32, message);
    return Buffer.from(digest);
}

/**
 * Client creates message 1 (64 bytes).
 *
 * @return 32 bytes hmac + 32 bytes clientEphemeralPk
 */
function message1(clientEphemeralPk: Buffer, discriminator: Buffer): Buffer {
    const clientHmac = hmac(clientEphemeralPk, discriminator);
    return Buffer.concat([clientHmac, clientEphemeralPk]);
}

/**
 * Server verifies client message 1.
 * @return client ephemeral public key on success, else throw exception.
 * @throws
 */
function verifyMessage1(msg1: Buffer, discriminator: Buffer): Buffer {
    const hmac = msg1.slice(0, 32);
    const clientEphemeralPk = msg1.slice(32, 64);
    if (assertHmac(hmac, clientEphemeralPk, discriminator)) {
        return clientEphemeralPk;
    }
    throw "Non matching discriminators";
}

/**
 * Server creates message 2 (64 bytes).
 * @return msg2: Buffer
 */
function message2(serverEphemeralPk: Buffer, discriminator: Buffer): Buffer {
    const serverHmac = hmac(serverEphemeralPk, discriminator);
    return Buffer.concat([serverHmac, serverEphemeralPk]);
}

/**
 * Client verifies first server message (message 2).
 * Return server ephemeral public key on success.
 * Throws on error.
 * @return serverEphemeralPk
 * @throws
 */
function verifyMessage2(msg2: Buffer, discriminator: Buffer): Buffer {
    const hmac = msg2.slice(0, 32);
    const serverEphemeralPk = msg2.slice(32, 64);
    if (assertHmac(hmac, serverEphemeralPk, discriminator)) {
        return serverEphemeralPk;
    }
    throw "Non matching discriminators";
}

/**
 * Client creates message 3 (208 bytes).
 * @return ciphertext: Buffer
 */
function message3(detachedSigA: Buffer, discriminator: Buffer, clientLongtermPk: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, clientData: Buffer | undefined): Buffer {
    if (!clientData) {
        clientData = Buffer.alloc(96).fill(0);
    }
    if (clientData.length > 96) {
        throw "Client data cannot exceed 96 bytes";
    }
    if (clientData.length < 96) {
        clientData = Buffer.concat([clientData, Buffer.alloc(96 - clientData.length).fill(0)]);
    }
    const message = Buffer.concat([detachedSigA, clientLongtermPk, clientData]);
    const nonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB]));
    return Buffer.from(secretBox(message, nonce, key));
}

/**
 * Server verifies message 3.
 * Return client longterm public key, the detachedSigA, and the arbitrary client data on success.
 * Throws exception on error.
 * @return [clientLongtermPk, detachedSigA, clientData]
 * @throws
 */
function verifyMessage3(ciphertext: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer): [Buffer, Buffer, Buffer] {
    const nonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB]));
    const msg3 = secretBoxOpen(ciphertext, nonce, key);

    if (msg3.length !== 64 + 32 + 96) {
        throw "Length mismatch decrypting message 3";
    }

    const detachedSigA = msg3.slice(0, 64);
    const clientLongtermPk = msg3.slice(64, 64+32);
    const clientData = msg3.slice(64+32);
    const msg = Buffer.concat([discriminator, serverLongtermPk, hashFn(sharedSecret_ab)]);

    if (!signVerifyDetached(msg, detachedSigA, clientLongtermPk)) {
        throw "Signature does not match";
    }

    return [clientLongtermPk, detachedSigA, clientData];
}

/**
 * Server creates its second message (message 4) (176 bytes).
 */
function message4(discriminator: Buffer, detachedSigA: Buffer, clientLongtermPk: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer, serverLongtermSk: Buffer, serverData: Buffer | undefined): Buffer {
    if (!serverData) {
        serverData = Buffer.alloc(96).fill(0);
    }
    if (serverData.length > 96) {
        throw "Client data cannot exceed 96 bytes";
    }
    if (serverData.length < 96) {
        serverData = Buffer.concat([serverData, Buffer.alloc(96 - serverData.length).fill(0)]);
    }
    const detachedSigB = signDetached(Buffer.concat([discriminator, detachedSigA, clientLongtermPk, hashFn(sharedSecret_ab)]), serverLongtermSk);
    const nonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]));
    return secretBox(Buffer.concat([detachedSigB, serverData]), nonce, key);
}

/**
 * Client verifies server message 2 (message 4).
 * @return serverData: Buffer
 * @throws on error
 */
function verifyMessage4(ciphertext: Buffer, detachedSigA: Buffer, clientLongtermPk: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer): Buffer {
    const nonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]));
    const unboxed = secretBoxOpen(ciphertext, nonce, key);
    const detachedSigB = unboxed.slice(0, 64);
    const serverData = unboxed.slice(64, 64+96);
    const msg = Buffer.concat([discriminator, detachedSigA, clientLongtermPk, hashFn(sharedSecret_ab)]);
    if (!signVerifyDetached(msg, detachedSigB, serverLongtermPk)) {
        throw "Signature does not match";
    }
    return serverData;
}

/**
 * On successful handshake return the arbitrary server 96 byte data buffer.
 * On unsuccessful throw exception.
 * @return Promise <{clientToServerKey, clientNonce, serverToClientKey, serverNonce, serverData}>
 * @throws
 */
export async function HandshakeAsClient(client: Client, clientLongtermSk: Buffer, clientLongtermPk: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, clientData?: Function | Buffer): Promise<HandshakeResult> {
    return new Promise( async (resolve, reject) => {
        try {
            await sodium.ready;

            // Make sure the discriminator is constant length
            discriminator = hashFn(discriminator);

            const clientEphemeralKeys = createEphemeralKeys();
            const clientEphemeralPk = clientEphemeralKeys.publicKey;
            const clientEphemeralSk = clientEphemeralKeys.secretKey;

            // First message from client (message 1)
            const msg1 = message1(clientEphemeralPk, discriminator);
            client.send(msg1);

            // First response from server (message 2)
            const msg2 = await new ByteSize(client).read(64);
            const serverEphemeralPk = verifyMessage2(msg2, discriminator);

            const sharedSecret_ab = clientSharedSecret_ab(clientEphemeralSk, serverEphemeralPk);
            const sharedSecret_aB = clientSharedSecret_aB(clientEphemeralSk, serverLongtermPk);

            // Second message from client (message 3)
            const detachedSigA = signDetached(Buffer.concat([discriminator, serverLongtermPk, hashFn(sharedSecret_ab)]), clientLongtermSk);
            if (typeof(clientData) === "function") {
                // Dynamically compute client data based on signature A.
                // This provides a way for client to provide PoW to the server if the server requires that due to some ongoing DDoS.
                clientData = clientData(detachedSigA);
            }
            if (!Buffer.isBuffer(clientData)) {
                clientData = undefined;
            }
            const msg3_ciphertext = message3(detachedSigA, discriminator, clientLongtermPk, sharedSecret_ab, sharedSecret_aB, clientData);
            client.send(msg3_ciphertext);

            const sharedSecret_Ab = clientSharedSecret_Ab(clientLongtermSk, serverEphemeralPk);

            // Second response from server (message 4)
            const msg4_ciphertext = await new ByteSize(client).read(176);
            const serverData = verifyMessage4(msg4_ciphertext, detachedSigA, clientLongtermPk, serverLongtermPk, discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab);

            const [clientToServerKey, clientNonce] = calcClientToServerKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, serverLongtermPk, serverEphemeralPk);
            const [serverToClientKey, serverNonce] = calcServerToClientKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, clientLongtermPk, clientEphemeralPk);

            resolve({peerLongtermPk: serverLongtermPk, clientToServerKey, clientNonce, serverToClientKey, serverNonce, peerData: serverData});
        }
        catch(e) {
            reject(e);
        }
    });
}

/**
 * On successful handshake return the client longterm public key the box keys and nonces and the arbitrary client 96 byte data buffer.
 * On failed handshake throw exception.
 * @return Promise<{clientLongtermPk, clientToServerKey, clientNonce, serverToClientKey, serverNonce, clientData}>
 * @throws
 */
export async function HandshakeAsServer(client: Client, serverLongtermSk: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, allowedClientKey?: Function | Buffer[], serverData?: Function | Buffer): Promise<HandshakeResult> {
    return new Promise( async (resolve, reject) => {
        try {
            await sodium.ready;

            // Make sure the discriminator is constant length
            discriminator = hashFn(discriminator);

            const serverEphemeralKeys = createEphemeralKeys();
            const serverEphemeralPk = serverEphemeralKeys.publicKey;
            const serverEphemeralSk = serverEphemeralKeys.secretKey;

            // Wait for first message from client (message 1)
            const msg1 = await new ByteSize(client).read(64);
            const clientEphemeralPk = verifyMessage1(msg1, discriminator);

            // Send first message from server (message 2)
            const msg2 = message2(serverEphemeralPk, discriminator);
            client.send(msg2);

            const sharedSecret_ab = serverSharedSecret_ab(serverEphemeralSk, clientEphemeralPk);
            const sharedSecret_aB = serverSharedSecret_aB(serverLongtermSk, clientEphemeralPk);

            // Wait for second message from client (message 3)
            const msg3_ciphertext = await new ByteSize(client).read(208);
            const [clientLongtermPk, detachedSigA, clientData] = verifyMessage3(msg3_ciphertext, serverLongtermPk, discriminator, sharedSecret_ab, sharedSecret_aB);

            if (typeof(serverData) === "function") {
                // The server can verify and/or check the client data.
                // This could be something like a PoW check on the detachedSigA to prevent DDoS attacks.
                // If it dislikes the clientData then it must throw an exception to abort this handshake.
                serverData = await serverData(clientData, detachedSigA);
            }
            if (!Buffer.isBuffer(serverData)) {
                serverData = undefined;
            }

            // Verify permissioned handshake for client longterm pk
            if (allowedClientKey) {
                if (typeof(allowedClientKey) === "function") {
                    if (!allowedClientKey(clientLongtermPk)) {
                        throw "Client longterm pk not allowed by function";
                    }
                }
                else if (Array.isArray(allowedClientKey)) {
                    if (!allowedClientKey.find( (pk) => Equals(pk, clientLongtermPk) )) {
                        throw "Client longterm pk not in list of allowed public keys";
                    }
                }
                else {
                    throw "Unknown client longterm pk validator";
                }
            }
            else {
                // WARNING: no allowedClientKey means to allow all clients connecting
                // Fall through
            }

            const sharedSecret_Ab = serverSharedSecret_Ab(serverEphemeralSk, clientLongtermPk);

            // Send second message from server (message 4)
            const msg4_ciphertext = message4(discriminator, detachedSigA, clientLongtermPk, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, serverLongtermSk, serverData);
            client.send(msg4_ciphertext);

            const [clientToServerKey, clientNonce] = calcClientToServerKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, serverLongtermPk, serverEphemeralPk);
            const [serverToClientKey, serverNonce] = calcServerToClientKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, clientLongtermPk, clientEphemeralPk);

            // Done
            resolve({peerLongtermPk: clientLongtermPk, clientToServerKey, clientNonce, serverToClientKey, serverNonce, peerData: clientData});
        }
        catch(e) {
            reject(e);
        }
    });
}
