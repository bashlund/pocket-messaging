import { TestSuite, Test, AfterAll, expect } from 'testyts';
import nacl from "tweetnacl";
import {box, unbox, randomBytes} from "../src/Crypto";

@TestSuite()
export class CryptoSpec {
    @Test()
    public encryption() {
        // TODO test box and unbox

        const chunk = Buffer.from("Hello World!");
        const outgoingNonce = Buffer.alloc(24).fill(1);
        const outgoingKey = Buffer.alloc(32).fill(2);
        const [ciphertext, nextNonce] = box(chunk, outgoingNonce, outgoingKey);
        expect.toBeFalse(ciphertext.equals(chunk));

        const incomingNonce = Buffer.alloc(24).fill(1);
        const incomingKey = outgoingKey;
        const [decrypted, nextNonce2] = unbox(ciphertext, incomingNonce, incomingKey) || [];
        expect.toBeTrue(Boolean(decrypted?.equals(chunk)));
        expect.toBeTrue(nextNonce2 && Boolean(nextNonce?.equals(nextNonce2)) || false);
    }

    @Test()
    public bytes() {
        let data = randomBytes(0);
        expect.toBeTrue(data.length == 0);

        data = randomBytes(11);
        expect.toBeTrue(data.length == 11);

        data = randomBytes(200);
        expect.toBeTrue(data.length == 200);
    }
}

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

