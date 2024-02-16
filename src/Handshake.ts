/**
 * A four way client-server handshake, as excellently described in https://ssbc.github.io/scuttlebutt-protocol-guide/,
 * with one added version byte and functionality to mitigate ddos attacks,
 * and added client/server data exchange for swapping application parameters.
 */

import sodium from "libsodium-wrappers";
import {ClientInterface, ByteSize} from "pocket-sockets";

import {
    HandshakeResult,
} from "./types";

type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer
};

// Single byte depicting the version of the handshake protocol.
const Version = Buffer.from([0]);

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
        throw new Error("Could not open box");
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
 * Client creates message 1 (65 bytes).
 *
 * @return 1 byte version + 32 bytes hmac + 32 bytes clientEphemeralPk
 */
function message1(clientEphemeralPk: Buffer, discriminator: Buffer): Buffer {
    if (clientEphemeralPk.length !== 32) {
        throw new Error("clientEphemeralPk must be 32 bytes");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    const clientHmac = hmac(clientEphemeralPk, discriminator);
    return Buffer.concat([Version, clientHmac, clientEphemeralPk]);
}

/**
 * Server verifies client message 1.
 * @return client ephemeral public key on success, else throw exception.
 * @throws
 */
function verifyMessage1(msg1: Buffer, discriminator: Buffer): Buffer {
    if (msg1.length !== 65) {
        throw new Error("Incoming message 1 must be 65 bytes long");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    const version = msg1.slice(0, 1);

    // Check so versions match.
    if (!Equals(version, Version)) {
        throw new Error("Mismatching version of the handshake");
    }

    const hmac = msg1.slice(1, 1+32);
    const clientEphemeralPk = msg1.slice(1+32, 1+32+32);
    if (assertHmac(hmac, clientEphemeralPk, discriminator)) {
        return clientEphemeralPk;
    }
    throw new Error("Non matching discriminators");
}

/**
 * Server creates message 2 (65 bytes).
 * @return msg2: Buffer
 */
function message2(difficulty: Buffer, serverEphemeralPk: Buffer, discriminator: Buffer): Buffer {
    if (difficulty.length !== 1) {
        throw new Error("Difficulty must be of length 1 bytes");
    }

    if (serverEphemeralPk.length !== 32) {
        throw new Error("ServerEphemeralPk must be of length 32 bytes");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    const serverHmac = hmac(Buffer.concat([difficulty, serverEphemeralPk]), discriminator);
    return Buffer.concat([serverHmac, difficulty, serverEphemeralPk]);
}

/**
 * Client verifies first server message (message 2: 65 bytes).
 * Return server ephemeral public key on success.
 * Throws on error.
 * @return serverEphemeralPk
 * @throws
 */
function verifyMessage2(msg2: Buffer, discriminator: Buffer): [Buffer, Buffer] {
    if (msg2.length !== 65) {
        throw new Error("Incoming message 2 must be of 65 bytes");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    const hmac = msg2.slice(0, 32);
    const difficulty = msg2.slice(32, 33);
    const serverEphemeralPk = msg2.slice(33, 65);

    if (assertHmac(hmac, Buffer.concat([difficulty, serverEphemeralPk]), discriminator)) {
        return [difficulty, serverEphemeralPk];
    }

    throw new Error("Non matching discriminators");
}

/**
 * Client creates its second message (message 3: variable length).
 * @return ciphertext: Buffer
 */
function message3(detachedSigA: Buffer, nonce: Buffer, discriminator: Buffer,
    clientLongtermPk: Buffer, sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, clientClock: number,
    clientData?: Buffer): Buffer
{
    if (detachedSigA.length !== 64) {
        throw new Error("detachedSigA must be 64 bytes");
    }

    if (nonce.length !== 4) {
        throw new Error("Nonce must be 4 bytes");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    if (clientLongtermPk.length !== 32) {
        throw new Error("ServerEphemeralPk must be of length 32 bytes");
    }

    if (sharedSecret_ab.length !== 32) {
        throw new Error("sharedSecret_ab must be of length 32 bytes");
    }

    if (sharedSecret_aB.length !== 32) {
        throw new Error("sharedSecret_aB must be of length 32 bytes");
    }

    if (clientClock < 0) {
        throw new Error("clientClock must be zero or positive");
    }

    if (!clientData) {
        clientData = Buffer.alloc(0);
    }

    if (clientData.length > 1024*60) {
        throw new Error("Client data cannot exceed 60 KiB");
    }

    let packedClientClock = Buffer.alloc(8);
    packedClientClock.writeBigInt64BE(BigInt(clientClock), 0);
    packedClientClock = packedClientClock.slice(2);  // remove first two empty bytes

    const message = Buffer.concat([detachedSigA, nonce, clientLongtermPk, packedClientClock, clientData]);
    const boxNonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB]));
    const ciphertext = Buffer.from(secretBox(message, boxNonce, key));
    const length = Buffer.alloc(2);  // Prepend ciphertext with two bytes describing length
    length.writeUInt16BE(ciphertext.length, 0);
    return Buffer.concat([length, ciphertext]);
}

/**
 * Server verifies message 3.
 * Return client longterm public key, the detachedSigA, and the arbitrary variable length client data on success.
 * Throws exception on error.
 * @return [nonce, clientLongtermPk, detachedSigA, clientClock, clientData]
 * @throws
 */
function verifyMessage3(msg3: Buffer, serverLongtermPk: Buffer, discriminator: Buffer,
    sharedSecret_ab: Buffer, sharedSecret_aB: Buffer): [Buffer, Buffer, Buffer, number, Buffer]
{
    if (serverLongtermPk.length !== 32) {
        throw new Error("serverLongtermPk must be of length 32 bytes");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    if (sharedSecret_ab.length !== 32) {
        throw new Error("sharedSecret_ab must be of length 32 bytes");
    }

    if (sharedSecret_aB.length !== 32) {
        throw new Error("sharedSecret_aB must be of length 32 bytes");
    }

    const length = msg3.readUInt16BE(0);
    const ciphertext = msg3.slice(2);
    if (ciphertext.length !== length) {
        throw new Error("Mismatching expected length of message 3");
    }

    const boxNonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB]));
    const unboxed = secretBoxOpen(ciphertext, boxNonce, key);
    const detachedSigA = unboxed.slice(0, 64);
    const nonce = unboxed.slice(64, 64+4);
    const clientLongtermPk = unboxed.slice(64+4, 64+4+32);
    const packedClientClock = unboxed.slice(64+4+32, 64+4+32+6);
    const clientData = unboxed.slice(64+4+32+6);

    const msg = Buffer.concat([nonce, discriminator, serverLongtermPk, hashFn(sharedSecret_ab)]);

    if (!signVerifyDetached(msg, detachedSigA, clientLongtermPk)) {
        throw new Error("Signature does not match");
    }

    const clientClock = Number(Buffer.concat([Buffer.alloc(2), packedClientClock]).readBigInt64BE(0));

    return [nonce, clientLongtermPk, detachedSigA, clientClock, clientData];
}

/**
 * Server creates its second message (message 4) (176 bytes).
 */
function message4(discriminator: Buffer, detachedSigA: Buffer, clientLongtermPk: Buffer,
    sharedSecret_ab: Buffer, sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer,
    serverLongtermSk: Buffer, serverClock: number, serverData?: Buffer): Buffer
{
    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    if (detachedSigA.length !== 64) {
        throw new Error("detachedSigA must be 64 bytes");
    }

    if (clientLongtermPk.length !== 32) {
        throw new Error("clientLongtermPk must be of length 32 bytes");
    }

    if (sharedSecret_ab.length !== 32) {
        throw new Error("sharedSecret_ab must be of length 32 bytes");
    }

    if (sharedSecret_aB.length !== 32) {
        throw new Error("sharedSecret_aB must be of length 32 bytes");
    }

    if (sharedSecret_Ab.length !== 32) {
        throw new Error("sharedSecret_Ab must be of length 32 bytes");
    }

    if (serverLongtermSk.length !== 64) {
        throw new Error("serverLongtermSk must be of length 64 bytes");
    }

    if (serverClock < 0) {
        throw new Error("serverClock must be zero or positive");
    }

    if (!serverData) {
        serverData = Buffer.alloc(0);
    }

    let packedServerClock = Buffer.alloc(8);
    packedServerClock.writeBigInt64BE(BigInt(serverClock), 0);
    packedServerClock = packedServerClock.slice(2);  // remove first two empty bytes

    const detachedSigB = signDetached(Buffer.concat([discriminator, detachedSigA, clientLongtermPk, hashFn(sharedSecret_ab)]), serverLongtermSk);
    const boxNonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]));
    const ciphertext = secretBox(Buffer.concat([detachedSigB, packedServerClock, serverData]), boxNonce, key);
    const length = Buffer.alloc(2);  // Prepend ciphertext with two bytes describing length
    length.writeUInt16BE(ciphertext.length, 0);
    return Buffer.concat([length, ciphertext]);
}

/**
 * Client verifies server message 2 (message 4).
 * @return [serverClock: number, serverData: Buffer]
 *  serverClock in milliseconds
 * @throws on error
 */
function verifyMessage4(msg4: Buffer, detachedSigA: Buffer, clientLongtermPk: Buffer,
    serverLongtermPk: Buffer, discriminator: Buffer, sharedSecret_ab: Buffer,
    sharedSecret_aB: Buffer, sharedSecret_Ab: Buffer): [number, Buffer]
{
    if (detachedSigA.length !== 64) {
        throw new Error("detachedSigA must be 64 bytes");
    }

    if (clientLongtermPk.length !== 32) {
        throw new Error("clientLongtermPk must be of length 32 bytes");
    }

    if (serverLongtermPk.length !== 32) {
        throw new Error("serverLongtermPk must be of length 32 bytes");
    }

    if (discriminator.length !== 32) {
        throw new Error("Discriminator must be 32 bytes");
    }

    if (sharedSecret_ab.length !== 32) {
        throw new Error("sharedSecret_ab must be of length 32 bytes");
    }

    if (sharedSecret_aB.length !== 32) {
        throw new Error("sharedSecret_aB must be of length 32 bytes");
    }

    if (sharedSecret_Ab.length !== 32) {
        throw new Error("sharedSecret_Ab must be of length 32 bytes");
    }

    const length = msg4.readUInt16BE(0);
    const ciphertext = msg4.slice(2);
    if (ciphertext.length !== length) {
        throw new Error("Mismatching expected length of message 4");
    }

    const boxNonce = Buffer.alloc(24).fill(0);
    const key = hashFn(Buffer.concat([discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab]));

    const unboxed = secretBoxOpen(ciphertext, boxNonce, key);
    const detachedSigB = unboxed.slice(0, 64);
    const serverClockPacked = unboxed.slice(64, 70);
    const serverData = unboxed.slice(70);
    const msg = Buffer.concat([discriminator, detachedSigA, clientLongtermPk, hashFn(sharedSecret_ab)]);
    if (!signVerifyDetached(msg, detachedSigB, serverLongtermPk)) {
        throw new Error("Signature does not match");
    }

    const serverClock = Number(Buffer.concat([Buffer.alloc(2), serverClockPacked]).readBigInt64BE(0));

    return [serverClock, serverData];
}

/**
 * @param difficulty number of nibbles to solve for
 */
function CalculateNonce(difficulty: number, serverEphemeralPk: Buffer): Buffer {
    const target = Buffer.from(serverEphemeralPk.toString("hex").slice(0, difficulty));
    let n = 0;
    let nonce = Buffer.alloc(4);
    const b = Buffer.alloc(4);
    while (!Equals(target, Buffer.from(nonce.toString("hex").slice(0, difficulty)))) {
        n++;
        b.writeUInt32BE(n);
        nonce = hashFn(b).slice(0, 4);
        if (n>=0xffffffff) {
            throw new Error("Nonce overflow");
        }
    }
    return nonce;
}

function VerifyNonce(difficulty: number, serverEphemeralPk: Buffer, nonce: Buffer): boolean {
    const target = Buffer.from(serverEphemeralPk.toString("hex").slice(0, difficulty));
    return Equals(target, Buffer.from(nonce.toString("hex").slice(0, difficulty)));
}

/**
 * On successful handshake return a populated HandshakeResult object.
 * On unsuccessful throw exception.
 * @return Promise <HandshakeResult>
 * @throws
 */
export async function HandshakeAsClient(
    client: ClientInterface,
    clientLongtermSk: Buffer,
    clientLongtermPk: Buffer,
    serverLongtermPk: Buffer,
    discriminator: Buffer,
    clientData?: Buffer,
    clock?: number,
    maxServerDataSize: number = 2048,
    timeout: number = 3000): Promise<HandshakeResult>
{
    clock = clock ?? Date.now();

    // We need this to take a delta later to adjust the clock.
    //
    const initialTimestamp = Date.now();

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
    const msg2 = await new ByteSize(client).read(65, timeout);

    // Before spending any more time, take the delta.
    //
    const delta = Date.now() - initialTimestamp;

    const [difficulty, serverEphemeralPk] = verifyMessage2(msg2, discriminator);

    const nonce = CalculateNonce(difficulty.readUInt8(0), serverEphemeralPk);

    const sharedSecret_ab = clientSharedSecret_ab(clientEphemeralSk, serverEphemeralPk);
    const sharedSecret_aB = clientSharedSecret_aB(clientEphemeralSk, serverLongtermPk);

    // Second message from client (message 3)
    //
    const clientClock = clock + delta;

    const detachedSigA = signDetached(Buffer.concat([nonce, discriminator, serverLongtermPk,
        hashFn(sharedSecret_ab)]), clientLongtermSk);

    const msg3 = message3(detachedSigA, nonce, discriminator, clientLongtermPk, sharedSecret_ab,
        sharedSecret_aB, clientClock, clientData);

    client.send(msg3);

    const sharedSecret_Ab = clientSharedSecret_Ab(clientLongtermSk, serverEphemeralPk);

    // Wait for second response from server (message 4)
    const lengthPrefix = await new ByteSize(client).read(2, timeout);
    const length = lengthPrefix.readUInt16BE(0);
    const FIXED_LENGTH = 70;  // 64 byte signature + 6 byte clock
    if (length - FIXED_LENGTH > maxServerDataSize) {
        throw new Error("Server data length too big");
    }

    const msg4_ciphertext = await new ByteSize(client).read(length, timeout);
    const msg4 = Buffer.concat([lengthPrefix, msg4_ciphertext]);

    const [serverClock, serverData] = verifyMessage4(msg4, detachedSigA, clientLongtermPk,
        serverLongtermPk, discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab);

    const [clientToServerKey, clientNonce] = calcClientToServerKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, serverLongtermPk, serverEphemeralPk);
    const [serverToClientKey, serverNonce] = calcServerToClientKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, clientLongtermPk, clientEphemeralPk);

    const handshakeParams = {
        longtermPk: clientLongtermPk,
        peerLongtermPk: serverLongtermPk,
        clientToServerKey,
        clientNonce,
        serverToClientKey,
        serverNonce,
        clockDiff: clientClock - serverClock,
        peerData: serverData,
    };

    return handshakeParams;
}

/**
 * On successful handshake return a populated HandshakeResult object.
 *
 * On failed handshake throw exception.
 *
 * @param client to send and retrieve data on
 * @param serverLongtermSk this side's long term secret key
 * @param serverLongtermPk this side's long term public key
 * @param discriminator arbitrary data that must exactly match the client discriminator data
 * @param allowedClientKeys if Buffer array it contains all client public keys allowed to handshake.
 *  If a function the function has to return true for the client to be allowed.
 *  If undefined then allow all clients to handshake.
 * @param serverData optional data to pass to the client upon successful handshake. Its length cannot
 *  exceed the client's maximum allowed length.
 * @param clock timestamp in milliseconds for when starting the handshake
 *  This value will be adjusted upwards to be as near as possible for when the clock was sent
 * @param difficulty is the number of nibbles the client is required to calculate to mitigate ddos
 *  attacks. Difficulty 6 is a lot. 8 is max.
 *  If the client does not provide a requested nonce then the handshake is aborted after the clients
 *  second message is retrieved.
 * @param maxClientDataSize the maximum length allowed for the client to pass its optional data.
 * @param timeout in milliseconds to wait for each message before aborting.
 * @return Promise<HandshakeResult>
 * @throws on error
 */
export async function HandshakeAsServer(
    client: ClientInterface,
    serverLongtermSk: Buffer,
    serverLongtermPk: Buffer,
    discriminator: Buffer,
    allowedClientKeys?: ((clientLongtermPk: Buffer) => boolean) | Buffer[],
    serverData?: Buffer,
    clock?: number,
    difficulty: number = 0,
    maxClientDataSize: number = 2048,
    timeout: number = 3000): Promise<HandshakeResult>
{
    clock = clock ?? Date.now();

    // We need this to take a delta later to adjust the clock.
    //
    const initialTimestamp = Date.now();

    if (difficulty > 8) {
        // We support 8 nibbles of nonce.
        throw new Error("Too high difficulty requested, max 8");
    }

    await sodium.ready;

    // Make sure the discriminator is constant length
    discriminator = hashFn(discriminator);

    const serverEphemeralKeys = createEphemeralKeys();
    const serverEphemeralPk = serverEphemeralKeys.publicKey;
    const serverEphemeralSk = serverEphemeralKeys.secretKey;

    // Wait for first message from client (message 1)
    const msg1 = await new ByteSize(client).read(65, timeout);
    const clientEphemeralPk = verifyMessage1(msg1, discriminator);

    // Send first message from server (message 2)
    const msg2 = message2(Buffer.from([difficulty]), serverEphemeralPk, discriminator);
    client.send(msg2);

    const sharedSecret_ab = serverSharedSecret_ab(serverEphemeralSk, clientEphemeralPk);
    const sharedSecret_aB = serverSharedSecret_aB(serverLongtermSk, clientEphemeralPk);

    // Wait for second message from client (message 3)
    const lengthPrefix = await new ByteSize(client).read(2, timeout + difficulty * 30000);
    const length = lengthPrefix.readUInt16BE(0);
    const FIXED_LENGTH = 106;  // incl. 6 byte clock
    if (length - FIXED_LENGTH > maxClientDataSize) {
        throw new Error("Client data length too big");
    }

    const msg3_ciphertext = await new ByteSize(client).read(length, timeout);

    // Before spending any more time, take the delta.
    //
    const delta = Date.now() - initialTimestamp;

    const msg3 = Buffer.concat([lengthPrefix, msg3_ciphertext]);

    const [nonce, clientLongtermPk, detachedSigA, clientClock, clientData] = verifyMessage3(msg3,
        serverLongtermPk, discriminator, sharedSecret_ab, sharedSecret_aB);

    if (!VerifyNonce(difficulty, serverEphemeralPk, nonce)) {
        throw new Error("Nonce does not verify");
    }

    // Verify permissioned handshake for client longterm pk
    if (allowedClientKeys) {
        if (typeof(allowedClientKeys) === "function") {
            if (!allowedClientKeys(clientLongtermPk)) {
                throw new Error(`Client longterm pk (${clientLongtermPk.toString("hex")} not allowed by function, IP: ${client.getRemoteAddress()}`);
            }
        }
        else if (Array.isArray(allowedClientKeys)) {
            if (!allowedClientKeys.find( (pk) => Equals(pk, clientLongtermPk) )) {
                throw new Error(`Client longterm pk (${clientLongtermPk.toString("hex")}) not in list of allowed public keys, IP: ${client.getRemoteAddress()}`);
            }
        }
        else {
            throw new Error("Unknown client longterm pk validator");
        }
    }
    else {
        // WARNING: no allowedClientKeys means to allow all clients connecting
        // Fall through
    }

    const sharedSecret_Ab = serverSharedSecret_Ab(serverEphemeralSk, clientLongtermPk);


    // Send second message from server (message 4)
    //
    const serverClock = clock + delta;

    const msg4 = message4(discriminator, detachedSigA, clientLongtermPk, sharedSecret_ab,
        sharedSecret_aB, sharedSecret_Ab, serverLongtermSk, serverClock, serverData);

    client.send(msg4);

    const [clientToServerKey, clientNonce] = calcClientToServerKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, serverLongtermPk, serverEphemeralPk);
    const [serverToClientKey, serverNonce] = calcServerToClientKey(discriminator, sharedSecret_ab, sharedSecret_aB, sharedSecret_Ab, clientLongtermPk, clientEphemeralPk);

    const handshakeParams = {
        longtermPk: serverLongtermPk,
        peerLongtermPk: clientLongtermPk,
        clientToServerKey,
        clientNonce,
        serverToClientKey,
        clockDiff: serverClock - clientClock,
        serverNonce,
        peerData: clientData,
    };

    // Done
    return handshakeParams;
}
