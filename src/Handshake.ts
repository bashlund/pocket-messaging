/**
 * A four way client-server handshake, as excellently described in https://ssbc.github.io/scuttlebutt-protocol-guide/,
 * with an added arbitrary 96 byte client/server data transmission.
 */

import {Client, ByteSize} from "../../pocket-sockets";
import nacl from "tweetnacl";
//@ts-ignore TODO: get types for this
import nacl_auth from "tweetnacl-auth";
//@ts-ignore TODO: get types for this
import ed2curve from "ed2curve"
import crypto from "crypto";

type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer
};

function createEphemeralKeys(): KeyPair {
    const keyPair = nacl.box.keyPair();
    return {
        publicKey: Buffer.from(keyPair.publicKey),
        secretKey: Buffer.from(keyPair.secretKey)
    };
}

function hmac(msg: Buffer, key: Buffer): Buffer {
    const hmac = nacl_auth(msg, key);
    return Buffer.from(hmac);
}

function assertHmac(clientHmac: Buffer, msg: Buffer, key: Buffer): boolean {
    const hmac2 = hmac(msg, key);
    return hmac2.equals(clientHmac);
}

function clientSharedSecret_ab(clientEphemeralSk: Buffer, serverEphemeralPk: Buffer): Buffer {
    return Buffer.from(nacl.scalarMult(clientEphemeralSk, serverEphemeralPk));
}

function serverSharedSecret_ab(serverEphemeralSk: Buffer, clientEphemeralPk: Buffer): Buffer {
    return Buffer.from(nacl.scalarMult(serverEphemeralSk, clientEphemeralPk));
}

function clientSharedSecret_aB(clientEphemeralPk: Buffer, serverLongtermPk: Buffer): Buffer {
    return Buffer.from(nacl.scalarMult(clientEphemeralPk, ed2curve.convertPublicKey(serverLongtermPk)));
}

function serverSharedSecret_aB(serverLongtermSk: Buffer, clientEphemeralPk: Buffer): Buffer {
    return Buffer.from(nacl.scalarMult(ed2curve.convertSecretKey(serverLongtermSk), clientEphemeralPk));
}

function clientSharedSecret_Ab(clientLongtermSk: Buffer, serverEphemeralPk: Buffer): Buffer {
    return Buffer.from(nacl.scalarMult(ed2curve.convertSecretKey(clientLongtermSk), serverEphemeralPk));
}

function serverSharedSecret_Ab(serverEphemeralSk: Buffer, clientLongtermPk: Buffer): Buffer {
    return Buffer.from(nacl.scalarMult(serverEphemeralSk, ed2curve.convertPublicKey(clientLongtermPk)));
}

function signDetached(msg: Buffer, secretKey: Buffer): Buffer {
    return Buffer.from(nacl.sign.detached(msg, secretKey));
}

function signVerifyDetached(msg: Buffer, sig: Buffer, publicKey: Buffer): boolean {
    return nacl.sign.detached.verify(msg, sig, publicKey);
}

function secretBox(msg: Buffer, nonce: Buffer, key: Buffer): Buffer {
    return Buffer.from(nacl.secretbox(msg, nonce, key));
}

function secretBoxOpen(ciphertext: Buffer, nonce: Buffer, key: Buffer): Buffer {
    const unboxed = nacl.secretbox.open(ciphertext, nonce, key);
    if (!unboxed) {
        throw "Could not open box";
    }
    return Buffer.from(unboxed);
}

function calcClientToServerKey(discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer, serverLongtermPk: Buffer, serverEphemeralPk: Buffer): [Buffer, Buffer] {
    const inner = sha256(sha256(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab])));
    const clientToServerKey = sha256(Buffer.concat([inner, serverLongtermPk]));
    const clientNonce = hmac(serverEphemeralPk, discriminator).slice(0, 24);
    return [clientToServerKey, clientNonce];
}

function calcServerToClientKey(discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer, clientLongtermPk: Buffer, clientEphemeralPk: Buffer): [Buffer, Buffer] {
    const inner = sha256(sha256(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab])));
    const serverToClientKey = sha256(Buffer.concat([inner, clientLongtermPk]));
    const serverNonce = hmac(clientEphemeralPk, discriminator).slice(0, 24);
    return [serverToClientKey, serverNonce];
}

function sha256(buf: Buffer): Buffer {
    const h = crypto.createHash("sha256");
    h.update(buf);
    return h.digest();
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
    const key = sha256(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB]));
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
    const key = sha256(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB]));
    const msg3 = secretBoxOpen(ciphertext, nonce, key);

    const detachedSigA = msg3.slice(0, 64);
    const clientLongtermPk = msg3.slice(64, 64+32);
    const clientData = msg3.slice(64+32);
    const msg = Buffer.concat([discriminator, serverLongtermPk, sha256(sharedSecret_ab)]);

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
    const detachedSigB = signDetached(Buffer.concat([discriminator, detachedSigA, clientLongtermPk, sha256(sharedSecret_ab)]), serverLongtermSk);
    const nonce = Buffer.alloc(24).fill(0);
    const key = sha256(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]));
    return secretBox(Buffer.concat([detachedSigB, serverData]), nonce, key);
}

/**
 * Client verifies server message 2 (message 4).
 * @return serverData: Buffer
 * @throws on error
 */
function verifyMessage4(ciphertext: Buffer, detachedSigA: Buffer, clientLongtermPk: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer): Buffer {
    const nonce = Buffer.alloc(24).fill(0);
    const key = sha256(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]));
    const unboxed = secretBoxOpen(ciphertext, nonce, key);
    const detachedSigB = unboxed.slice(0, 64);
    const serverData = unboxed.slice(64, 64+96);
    const msg = Buffer.concat([discriminator, detachedSigA, clientLongtermPk, sha256(sharedSecret_ab)]);
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
export async function HandshakeAsClient(client: Client, clientLongtermSk: Buffer, clientLongtermPk: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, clientData?: Function | Buffer): Promise<{clientToServerKey: Buffer, clientNonce: Buffer, serverToClientKey: Buffer, serverNonce: Buffer, serverData: Buffer}> {
    return new Promise( async (resolve, reject) => {
        try {
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
            const detachedSigA = signDetached(Buffer.concat([discriminator, serverLongtermPk, sha256(sharedSecret_ab)]), clientLongtermSk);
            if (typeof(clientData) === "function") {
                // Dynamically compute client data based on signature A.
                // This provides a way for cliennt to provide PoW to the server if the server requires that due to some ongoing DDoS.
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

            resolve({clientToServerKey, clientNonce, serverToClientKey, serverNonce, serverData});
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
export async function HandshakeAsServer(client: Client, serverLongtermSk: Buffer, serverLongtermPk: Buffer, discriminator: Buffer, allowedClientKey?: Function | Buffer[], serverData?: Function | Buffer): Promise<{clientLongtermPk: Buffer, clientToServerKey: Buffer, clientNonce: Buffer, serverToClientKey: Buffer, serverNonce: Buffer, clientData: Buffer}> {
    return new Promise( async (resolve, reject) => {
        try {
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
                // If it dislikes the clientData then it will throw an exception and abort this handshake.
                serverData = serverData(clientData, detachedSigA);
            }
            if (!Buffer.isBuffer(serverData)) {
                serverData = undefined;
            }

            // Verify permissioned handshake for client longterm pk
            if (allowedClientKey) {
                if (typeof(allowedClientKey) === "function") {
                    if (!allowedClientKey(clientLongtermPk)) {
                        throw "Cling longterm pk not allowed by function";
                    }
                }
                else if (Array.isArray(allowedClientKey)) {
                    if (!allowedClientKey.find( (pk) => pk.equals(clientLongtermPk) )) {
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
            resolve({clientLongtermPk, clientToServerKey, clientNonce, serverToClientKey, serverNonce, clientData});
        }
        catch(e) {
            reject(e);
        }
    });
}
