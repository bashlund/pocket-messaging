import nacl from "tweetnacl";

export function encrypt(message: Buffer, peerPublicKey: Buffer, secretKey: Buffer): Buffer {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const box = nacl.box(message, nonce, peerPublicKey, secretKey);
    const length = 4 + nonce.length + box.length;
    const encrypted = Buffer.alloc(length);
    encrypted.writeUInt32LE(length, 0);
    encrypted.set(nonce, 4);
    encrypted.set(box, 4 + nonce.length);
    return encrypted;
}

export function decrypt(chunk: Buffer, peerPublicKey: Buffer, secretKey: Buffer): Buffer | undefined {
    const nonce     = new Uint8Array(chunk.slice(4, 4 + nacl.secretbox.nonceLength));
    const message   = chunk.slice(4 + nacl.secretbox.nonceLength);
    const decrypted = nacl.box.open(message, nonce, peerPublicKey, secretKey);
    if (!decrypted) {
        return undefined;
    }
    const decryptedBuffer = Buffer.alloc(decrypted.length);
    decryptedBuffer.set(decrypted);
    return decryptedBuffer;
}

export function randomBytes(count: number) {
    return nacl.randomBytes(count);
}
