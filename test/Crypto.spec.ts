import { TestSuite, Test, AfterAll, expect } from 'testyts';
import {box, unbox, randomBytes, init} from "../src/Crypto";

@TestSuite()
export class CryptoSpec {
    @Test()
    public async encryption() {
        // TODO test box and unbox

        await init();  // libsodium

        const chunk = Buffer.from("Hello World!");
        const outgoingNonce = Buffer.alloc(24).fill(1);
        const outgoingKey = Buffer.alloc(32).fill(2);
        const [ciphertext, nextNonce] = box(chunk, outgoingNonce, outgoingKey);
        expect.toBeFalse(ciphertext.equals(chunk));
        expect.toBeTrue(typeof(ciphertext) == "object");
        expect.toBeTrue(Buffer.isBuffer(ciphertext) == true);

        const incomingNonce = Buffer.alloc(24).fill(1);
        const incomingKey = outgoingKey;
        const [decrypted, nextNonce2] = unbox(ciphertext, incomingNonce, incomingKey) || [];
        expect.toBeTrue(Boolean(decrypted?.equals(chunk)));
        expect.toBeTrue(nextNonce2 && Boolean(nextNonce?.equals(nextNonce2)) || false);
    }

    @Test()
    public async bytes2() {
        await init();  // libsodium

        let data = randomBytes(0);
        expect.toBeTrue(data.length == 0);

        data = randomBytes(11);
        expect.toBeTrue(data.length == 11);

        data = randomBytes(200);
        expect.toBeTrue(data.length == 200);
    }
}
