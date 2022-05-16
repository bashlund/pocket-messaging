import { TestSuite, Test, AfterAll, BeforeAll, expect } from 'testyts';

import {genKeyPair, init} from "../src/Crypto";
import {CreatePair, Client} from "pocket-sockets";
import {HandshakeAsClient, HandshakeAsServer} from "../src/Handshake";
const assert = require("assert");

type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer
};

@TestSuite()
export class HandshakeSpec {
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
                const ret = await HandshakeAsServer(this.socket2, this.keyPairServer.secretKey, this.keyPairServer.publicKey, discriminator, allowedClientKey, serverData);
                //console.log("SERVER HANDSHAKE", );
                //console.log(`clientLongtermPk: ${ret[0].toString("hex")}`);
                //console.log(`clientToServerKey: ${ret[1].toString("hex")}`);
                //console.log(`clientNonce: ${ret[2].toString("hex")}`);
                //console.log(`serverToClientKey: ${ret[3].toString("hex")}`);
                //console.log(`serverNonce: ${ret[4].toString("hex")}`);
                //console.log(`clientData: ${ret[5].toString("hex")}`);
                this.socket2.close();
            }
            catch(e) {
                console.error("server got error", e);
            }
        });

        try {
            const ret = await HandshakeAsClient(this.socket1, this.keyPairClient.secretKey, this.keyPairClient.publicKey, this.keyPairServer.publicKey, discriminator, clientData);
            //console.log("CLIENT HANDSHAKE",);
            //console.log(`clientToServerKey: ${ret[0].toString("hex")}`);
            //console.log(`clientNonce: ${ret[1].toString("hex")}`);
            //console.log(`serverToClientKey: ${ret[2].toString("hex")}`);
            //console.log(`serverNonce: ${ret[3].toString("hex")}`);
            //console.log(`serverData: ${ret[4].toString("hex")}`);
            this.socket1.close();
        }
        catch(e) {
            console.error("client got error", e);
        }
    }
}
