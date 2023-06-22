import { TestSuite, Test, AfterAll, BeforeAll, expect } from 'testyts';

import {genKeyPair, init} from "../src/Crypto";
import {CreatePair, Client} from "pocket-sockets";
import {HandshakeAsClient, HandshakeAsServer} from "../src/Handshake";
import {EncryptedClient} from "../src/EncryptedClient";
const assert = require("assert");

type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer
};

@TestSuite()
export class EncryptedClientSpec {
    socket1: Client;
    socket2: Client;
    keyPairClient: KeyPair;
    keyPairServer: KeyPair;

    constructor() {
        [this.socket1, this.socket2] = CreatePair();
        this.keyPairClient = {publicKey: Buffer.alloc(0), secretKey: Buffer.alloc(0)};
        this.keyPairServer  = {publicKey: Buffer.alloc(0), secretKey: Buffer.alloc(0)};
    }

    @BeforeAll()
    async init() {
        await init();
        this.keyPairClient = genKeyPair();
        this.keyPairServer = genKeyPair();
    }

    @Test()
    public async handshake() {
        const discriminator = Buffer.from("hello");
        const clientData = Buffer.from("ABABBBABA");

        process.nextTick( async () => {
            const allowedClientKey: Buffer[] = [this.keyPairClient.publicKey];
            const serverData = Buffer.from("abbbaaa");
            try {
                const handshakeResult = await HandshakeAsServer(this.socket2, this.keyPairServer.secretKey, this.keyPairServer.publicKey, discriminator, allowedClientKey, serverData);

                const encryptedSocket2 = new EncryptedClient(this.socket2,
                    handshakeResult.serverToClientKey,
                    handshakeResult.serverNonce,
                    handshakeResult.clientToServerKey,
                    handshakeResult.clientNonce,
                    handshakeResult.peerLongtermPk);

                await encryptedSocket2.init();

                await sleep(100);

                this.socket2.onData( (data: Buffer) => {
                    // TODO this assert must throw properly
                    assert(data.length > 5);
                });

                encryptedSocket2.onData( (data: Buffer) => {
                    // TODO this assert must throw properly
                    assert(data.toString() === "World");
                });

                encryptedSocket2.send(Buffer.from("Hello"));

                await sleep(100);

                this.socket2.close();
            }
            catch(e) {
                console.error("server got error", e);
            }
        });

        try {
            const handshakeResult = await HandshakeAsClient(this.socket1, this.keyPairClient.secretKey, this.keyPairClient.publicKey, this.keyPairServer.publicKey, discriminator, clientData);

            const encryptedSocket1 = new EncryptedClient(this.socket1,
                handshakeResult.clientToServerKey,
                handshakeResult.clientNonce,
                handshakeResult.serverToClientKey,
                handshakeResult.serverNonce,
                handshakeResult.peerLongtermPk);

            await encryptedSocket1.init();

            this.socket1.onData( (data: Buffer) => {
                //console.error("socket1 raw data", data);
                // TODO this assert must throw properly
                assert(data.length > 5);
            });

            encryptedSocket1.onData( (data: Buffer) => {
                //console.error("socket1 decrypted data", data);
                // TODO this assert must throw properly
                assert(data.toString() === "Hello");
                encryptedSocket1.send(Buffer.from("World"));
            });

            await sleep(200);

            this.socket1.close();
        }
        catch(e) {
            console.error("client got error", e);
        }
    }
}

async function sleep(ms: number) {
    return new Promise( (resolve) => {
        setTimeout(resolve, ms);
    });
}
