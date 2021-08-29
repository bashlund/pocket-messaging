import { TestSuite, Test, AfterAll, expect } from 'testyts';
import nacl from "tweetnacl";

import EventEmitter from "eventemitter3";

import {Messaging, once, Header} from "../";
import {encrypt, decrypt} from "../src/Crypto";
import {CreatePair, AbstractClient} from "../../pocket-sockets";

@TestSuite()
export class MessagingSpec {
    socket1: AbstractClient;
    socket2: AbstractClient;
    messaging1: Messaging;
    messaging2: Messaging;
    eventEmitter1: EventEmitter;
    eventEmitter2: EventEmitter;

    constructor() {
        [this.socket1, this.socket2] = CreatePair();
        this.messaging1 = new Messaging(this.socket1);
        this.messaging2 = new Messaging(this.socket2);
        this.eventEmitter1 = this.messaging1.getEventEmitter();
        this.eventEmitter2 = this.messaging1.getEventEmitter();
    }

    @AfterAll()
    public shutdown() {
        this.messaging1.close();
        expect.toBeTrue(this.messaging1.isOpen() === false);
        this.messaging2.close();
        expect.toBeTrue(this.messaging2.isOpen() === false);
    }

    @Test()
    public basics() {
        expect.toBeTrue(this.eventEmitter1 != null);
        //@ts-ignore protected function
        const allEMs: EventEmitter[] = this.messaging1.getAllEventEmitters();
        expect.toBeTrue(allEMs.length === 1);
        expect.toBeTrue(allEMs[0] === this.eventEmitter1);

        expect.toBeTrue(this.messaging1.isOpen() === false);
        this.messaging1.open();
        expect.toBeTrue(this.messaging1.isOpen());

        //@ts-ignore protected function
        const msgId1 = this.messaging1.generateMsgId();
        expect.toBeTrue(msgId1.length === 4);

        //@ts-ignore protected function
        const msgId2 = this.messaging1.generateMsgId();
        expect.toBeTrue(msgId2.length === 4);
        expect.toBeTrue(msgId1.compare(msgId2) !== 0);

        const header: Header = {
            version: 0,
            target: Buffer.from("ping"),
            msgId: msgId1,
            dataLength: 33,
            config: 2
        };
        //@ts-ignore protected function
        const headerBuffer = this.messaging1.encodeHeader(header);
        expect.toBeTrue(headerBuffer.length === 11 + header.target.length);
        const messageBuffer = Buffer.concat([headerBuffer, Buffer.alloc(33).fill(33)]);
        //@ts-ignore protected function
        const ret = this.messaging1.decodeHeader(messageBuffer);
        expect.toBeTrue(ret !== undefined);
        if (!ret) return; //@ts-chillax trust me on this one
        const [header2, data2] = ret;
        expect.toBeTrue(header2 !== undefined);
        expect.toBeTrue(header2.version === 0);
        expect.toBeTrue(header2.target.length === 4);
        expect.toBeTrue(data2 !== undefined);
        expect.toBeTrue(data2.length === 33);
        expect.toBeTrue(data2.compare(Buffer.alloc(33).fill(33)) === 0);

        let buffers: Buffer[] = [];
        //@ts-ignore protected function
        let extracted = this.messaging1.extractBuffer(buffers, 100);
        expect.toBeTrue(extracted === undefined);
        buffers = [Buffer.from("abc"), Buffer.from("def")];
        //@ts-ignore protected function
        extracted = this.messaging1.extractBuffer(buffers, 100);
        expect.toBeTrue(extracted === undefined);
        //@ts-ignore protected function
        extracted = this.messaging1.extractBuffer(buffers, 1);
        expect.toBeTrue(extracted !== undefined);
        if (!extracted) return; //@ts-chillax trust me on this one
        expect.toBeTrue(extracted.compare(Buffer.from("a")) === 0);
        expect.toBeTrue(buffers.length === 2);
        expect.toBeTrue(buffers[0].length === 2);
        //@ts-ignore protected function
        extracted = this.messaging1.extractBuffer(buffers, 5);
        expect.toBeTrue(extracted !== undefined);
        if (!extracted) return; //@ts-chillax trust me on this one
        expect.toBeTrue(extracted.compare(Buffer.from("bcdef")) === 0);
        expect.toBeTrue(buffers.length === 0);
    }

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

    /**
     * Poke and test the eventsystem on single messaging instance.
     */
    @Test()
    public async events() {
        process.nextTick( () => {
            //@ts-ignore protected function
            this.messaging1.emitEvent([this.eventEmitter1], "error", 111);
        });

        let value = await once(this.eventEmitter1, "error");
        expect.toBeTrue(value === 111);

        process.nextTick( () => {
            //@ts-ignore protected function
            this.messaging1.emitEvent([this.eventEmitter1], "error", 112);
            //@ts-ignore protected function
            this.messaging1.emitEvent([this.eventEmitter1], "reply", 113);
        });
        value = await once(this.eventEmitter1, "reply");
        expect.toBeTrue(value === 113);

        process.nextTick( () => {
            //@ts-ignore protected function
            this.messaging1.socketError(Buffer.from("hello"));
        });

        let accept: Function;
        const p = new Promise( (accept2) => {
            accept = accept2;
        });
        this.eventEmitter1.on("error", (err) => {
            expect.toBeTrue(err !== undefined);
            expect.toBeTrue(err.error.length === 5);
            accept();
        });

        let buf = await once(this.eventEmitter1, "mixed");
        await p;
    }

    /**
     * Try communicating between two Messaging instances using leveraging the virtual socket pair.
     */
    @Test()
    public async communication() {
        const data = Buffer.from("Hello World!");
        this.messaging1.open();
        this.messaging2.open();

        const ee2 = this.messaging2.getEventEmitter();
        expect.toBeTrue(ee2 !== undefined, "Expecting eventemitter returned");

        process.nextTick( async () => {
            const ee1a = this.messaging1.send("ping", Buffer.from("A"), 10000, true);
            expect.toBeTrue(ee1a !== undefined, "Expecting eventemitter returned");
            if (!ee1a) return;  //@ts-chillax

            const reply = await once(ee1a, "reply");

            // This will emit a close event
            this.messaging1.close();
        });

        const event = await once(ee2, "route");
        const ee2a = this.messaging2.send(event.fromMsgId, Buffer.from("B"), 10000);
        expect.toBeTrue(ee2a !== undefined, "Expecting eventemitter returned");
        if (!ee2a) return;

        const reply = await once(ee2a, "mixed");  // this also catched close event
        expect.toBeTrue(reply !== undefined);
        expect.toBeTrue(reply.type === "close");
    }
}
