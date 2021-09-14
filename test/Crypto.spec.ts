import { TestSuite, Test, AfterAll, expect } from 'testyts';
import nacl from "tweetnacl";
import {encrypt, decrypt, randomBytes} from "../src/Crypto";

@TestSuite()
export class CryptoSpec {
    @Test()
    public encryption() {
        const keyPair = nacl.box.keyPair();
        const keyPairPeer = nacl.box.keyPair();
        const peerPublicKey = keyPairPeer.publicKey;
        const message = Buffer.from("Hello World");
        const encrypted = encrypt(message, Buffer.from(peerPublicKey), Buffer.from(keyPair.secretKey));
        expect.toBeTrue(encrypted !== undefined);
        expect.toBeTrue(encrypted.toString() !== "Hello World");
        const decrypted = decrypt(encrypted, Buffer.from(peerPublicKey), Buffer.from(keyPair.secretKey));
        expect.toBeTrue(decrypted !== undefined);
        //@ts-chillax
        if (!decrypted) return;
        expect.toBeTrue(decrypted.toString() === "Hello World");
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
