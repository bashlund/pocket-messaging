import sodium from "libsodium-wrappers";

export async function init() {
    await sodium.ready;
}

function increaseNonce(nonceOriginal: Buffer): Buffer {
    const nonce = Buffer.from(nonceOriginal);
    for (let index=nonce.length-1; index>=0; index--) {
        const value = nonce.readUInt8(index);
        if (value < 255) {
            nonce.writeUInt8(value + 1, index);
            break;
        }
        nonce.writeUInt8(0, index);
    }
    return nonce;
}

/**
 * Box a message and return it.
 * Will increase nonce two times and return the next nonce to be used.
 *
 * @param {Buffer} message The message to be encrypted (max length 65535 bytes)
 * @param {Buffer} nonce An unused nonce to use (24 bytes)
 * @param {Buffer} key The key to encrypt with (32 bytes)
 * @return [boxedMessage, nextNonce]
 * @throws
 */
export function box(message: Buffer, nonce: Buffer, key: Buffer): [Buffer, Buffer] {
    if (message.length > 65535) {
        throw new Error("Maximum message length is 65535 when boxing it");
    }
    const encryptedBody = sodium.crypto_secretbox_easy(message, nonce, key);
    const headerNonce = increaseNonce(nonce);

    const bodyAuthTag = Buffer.from(encryptedBody.slice(0, 16));
    const bodyLength = Buffer.alloc(2);
    bodyLength.writeUInt16BE(message.length, 0);

    const header = Buffer.concat([bodyLength, bodyAuthTag]);  // 18 bytes
    const encryptedHeader = sodium.crypto_secretbox_easy(header, headerNonce, key);  // 34 bytes
    const nextNonce = increaseNonce(headerNonce);

    const ciphertext = Buffer.concat([Buffer.from(encryptedHeader), Buffer.from(encryptedBody.slice(16))]);
    return [ciphertext, nextNonce];
}

/**
 * Will increase nonce two times and return the next nonce to be used.
 * Returns undefined if not enough data available.
 *
 * @param {Buffer} ciphertext The ciphertext to be decrypted
 * @param {Buffer} nonce The first nonce to decrypt with
 * @param {Buffer} key The key to decrypt with
 * @return [unboxedMessage: Buffer, nextNonce: Buffer, bytesConsumed: number] | undefined
 * @throws
 */
export function unbox(ciphertext: Buffer, nonce: Buffer, key: Buffer): [Buffer, Buffer, number] | undefined {
    if (ciphertext.length < 34) {
        // Not enough data available.
        return undefined;
    }
    const encrypted_header = ciphertext.slice(0, 34);
    const headerNonce = increaseNonce(nonce);
    const headerArray = sodium.crypto_secretbox_open_easy(encrypted_header, headerNonce, key);
    if (!headerArray) {
        throw new Error("Could not unbox header");
    }
    const header = Buffer.from(headerArray);

    const bodyLength = header.readUInt16BE(0);
    if (ciphertext.length < 34 + bodyLength) {
        // Not enough data available.
        return undefined;
    }
    const encryptedBody = ciphertext.slice(34, 34 + bodyLength);
    const body = sodium.crypto_secretbox_open_easy(Buffer.concat([header.slice(2), encryptedBody]), nonce, key);
    if (!body) {
        throw new Error("Could not unbox body");
    }

    const nextNonce = increaseNonce(headerNonce);
    return [Buffer.from(body), nextNonce, 34 + bodyLength];
}

export function randomBytes(count: number) {
    return sodium.randombytes_buf(count);
}

type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer
};

export function genKeyPair(): KeyPair {
    const keyPair = sodium.crypto_sign_keypair();
    return {
        publicKey: Buffer.from(keyPair.publicKey),
        secretKey: Buffer.from(keyPair.privateKey)
    };
}
