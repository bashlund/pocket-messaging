import { TestSuite, Test, AfterAll, expect } from 'testyts';

import EventEmitter from "eventemitter3";

import {Messaging, once, Header, EventType, SentMessage, TimeoutEvent} from "../";
import {CreatePair, Client} from "../../pocket-sockets";

const assert = require("assert");

@TestSuite()
export class MessagingSpec {
    socket1: Client;
    socket2: Client;
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

        let buf = await once(this.eventEmitter1, "any");
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
            if (!ee1a || !ee1a.eventEmitter) return;  //@ts-chillax

            const reply = await once(ee1a.eventEmitter, "reply");

            // This will emit a close event
            this.messaging1.close();
        });

        const event = await once(ee2, "route");
        const ee2a = this.messaging2.send(event.fromMsgId, Buffer.from("B"), 10000);
        expect.toBeTrue(ee2a !== undefined, "Expecting eventemitter returned");
        if (!ee2a || !ee2a.eventEmitter) return;

        const reply = await once(ee2a.eventEmitter, "any");  // this also catched close event
        expect.toBeTrue(reply !== undefined);
        expect.toBeTrue(reply.type === "close");
    }
}

@TestSuite()
export class MessagingConstructor {
    @Test()
    public default_state() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert(Object.keys(messaging.pendingReply).length == 0);

        assert(!messaging.isOpened);
        assert(!messaging.isClosed);
        assert(!messaging.encryptionKeys);

        assert(messaging.dispatchLimit == -1);
        assert(messaging.isBusyOut == 0);
        assert(messaging.isBusyIn == 0);
        assert(messaging.instanceId.length == (8 * 2));

        assert(messaging.incomingQueue.encrypted.length == 0);
        assert(messaging.incomingQueue.decrypted.length == 0);
        assert(messaging.incomingQueue.messages.length == 0);

        assert(messaging.outgoingQueue.unencrypted.length == 0);
        assert(messaging.outgoingQueue.encrypted.length == 0);

        assert(messaging.eventEmitter);
    }
}

@TestSuite()
export class MessagingSetEncrypted {
    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            assert(!messaging.getPeerPublicKey());
            assert(!messaging.encryptionKeys);
            const outKey = Buffer.alloc(32);
            const outNonce = Buffer.alloc(24);
            const inKey = Buffer.alloc(32);
            const inNonce = Buffer.alloc(24);
            const peerPubKey = Buffer.alloc(32);
            await messaging.setEncrypted(outKey, outNonce, inKey, inNonce, peerPubKey);
            assert(messaging.getPeerPublicKey());
            assert(messaging.encryptionKeys);
        });
    }
}

@TestSuite()
export class MessagingSetUnencrypted {
    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            const outKey = Buffer.alloc(32);
            const outNonce = Buffer.alloc(24);
            const inKey = Buffer.alloc(32);
            const inNonce = Buffer.alloc(24);
            const peerPubKey = Buffer.alloc(32);
            await messaging.setEncrypted(outKey, outNonce, inKey, inNonce, peerPubKey);
            assert(messaging.encryptionKeys);
            messaging.setUnencrypted();
            assert(!messaging.encryptionKeys);
        });
    }
}

@TestSuite()
export class MessagingOpen {
    @Test()
    public already_closed() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            messaging.isClosed = true;
            assert(messaging.isOpened == false);
            messaging.open();
            assert(messaging.isOpened == false);
        });
    }

    @Test()
    public already_opened() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            messaging.isOpened = true;
            let flag = false;
            // Expected to be called only on success
            // @ts-ignore: protected method
            messaging.checkTimeouts = function() {
                flag = true;
            };
            messaging.open();
            assert(messaging.isOpened == true);
            assert(flag == false); // No change
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            let flag = false;
            // Expected to be called only on success
            // @ts-ignore: protected method
            messaging.checkTimeouts = function() {
                flag = true;
            };
            assert(messaging.isOpened == false);
            assert(flag == false);
            messaging.open();
            assert(messaging.isOpened == true);
            // @ts-ignore: expected to be modified by custom checkTimeouts
            assert(flag == true);
        });
    }
}

@TestSuite()
export class MessagingClose {
    @Test()
    public already_closed() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            let flag = false;
            messaging.socket.close = function() {
                flag = true;
            }
            assert(flag == false);
            messaging.close();
            assert(flag == false);
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            assert(messaging.isClosed == false);
            assert(messaging.isOpened == false);
            messaging.open();
            assert(messaging.isOpened == true);
            messaging.close();
            assert(messaging.isClosed == true);
        });
    }
}

@TestSuite()
export class MessagingCorkUncork {
    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            messaging.uncork(30);
            assert(messaging.dispatchLimit == 30);
            messaging.cork();
            assert(messaging.dispatchLimit == 0);
        });
    }

    @Test()
    public uncork_without_parameters() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            assert(messaging.dispatchLimit == -1);
            messaging.uncork(30);
            assert(messaging.dispatchLimit == 30);
            messaging.uncork();
            assert(messaging.dispatchLimit == -1);
        });
    }
}

@TestSuite()
export class MessagingSend {
    @Test()
    public not_open_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            assert(messaging.isOpened == false);
            assert(Object.keys(messaging.pendingReply).length == 0);
            messaging.send(Buffer.from(""));
            assert(Object.keys(messaging.pendingReply).length == 0);
        });
    }

    @Test()
    public isClosed_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            messaging.isClosed = true;
            assert(Object.keys(messaging.pendingReply).length == 0);
            messaging.send(Buffer.from(""));
            assert(Object.keys(messaging.pendingReply).length == 0);
        });
    }

    @Test()
    public exceed_target_length() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.throws(function() {
            assert(Object.keys(messaging.pendingReply).length == 0);
            messaging.isOpened = true;
            messaging.isClosed = false;
            messaging.send(Buffer.alloc(256).fill(256));
            assert(Object.keys(messaging.pendingReply).length == 0);
        }, /target length cannot exceed 255 bytes/);
    }

    @Test()
    public successful_call_no_reply() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            assert(messaging.outgoingQueue.unencrypted.length == 0);
            assert(Object.keys(messaging.pendingReply).length == 0);
            messaging.isOpened = true;
            messaging.isClosed = false;
            const replyStatus = messaging.send(Buffer.alloc(255).fill(255));
            assert(messaging.outgoingQueue.unencrypted.length == 1 + 1);
            assert(Object.keys(messaging.pendingReply).length == 0);
            assert(replyStatus !== undefined);
            assert(replyStatus && replyStatus.msgId !== undefined);
        });
    }

    @Test()
    public successful_call_expectingReply() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            assert(messaging.outgoingQueue.unencrypted.length == 0);
            assert(Object.keys(messaging.pendingReply).length == 0);
            messaging.isOpened = true;
            messaging.isClosed = false;
            const replyStatus = messaging.send(Buffer.alloc(255).fill(255), undefined, 1);
            assert(messaging.outgoingQueue.unencrypted.length == 1 + 1);
            assert(Object.keys(messaging.pendingReply).length == 1);
            assert(replyStatus?.eventEmitter instanceof EventEmitter);
        });
    }
}

@TestSuite()
export class MessagingEncodeHeader {
    @Test()
    public target_length_exceeded() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.throws(function() {
            //@ts-ignore protected function
            const id = messaging.generateMsgId();
            const header: Header = {
                version: 0,
                target: Buffer.alloc(256).fill(256),
                msgId: id,
                dataLength: 33,
                config: 2
            };
            //@ts-ignore protected function
            messaging.encodeHeader(header);
        }, /Target length cannot exceed 255 bytes./);
    }

    @Test()
    public msgId_length_exceeded() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.throws(function() {
            const header: Header = {
                version: 0,
                target: Buffer.alloc(255).fill(255),
                msgId: Buffer.from(""),
                dataLength: 33,
                config: 2
            };
            //@ts-ignore protected function
            messaging.encodeHeader(header);
        }, /msgId length must be exactly 4 bytes long./);
    }
}

@TestSuite()
export class MessagingDecodeHeader {
    @Test()
    public unsupported_version() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.throws(function() {
            //@ts-ignore protected function
            const id = messaging.generateMsgId();
            const header: Header = {
                version: 0,
                target: Buffer.alloc(255).fill(255),
                msgId: id,
                dataLength: 33,
                config: 2
            };
            //@ts-ignore protected function
            let encodedHeader = messaging.encodeHeader(header);
            encodedHeader.writeUInt8(255);
            //@ts-ignore protected function
            messaging.decodeHeader(encodedHeader);
        }, /Unexpected version nr. Only supporting version 0./);
    }

    @Test()
    public buffer_length_mismatch() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.throws(function() {
            //@ts-ignore protected function
            const id = messaging.generateMsgId();
            const header: Header = {
                version: 0,
                target: Buffer.alloc(255).fill(255),
                msgId: id,
                dataLength: 33,
                config: 2
            };
            //@ts-ignore protected function
            let encodedHeader = messaging.encodeHeader(header);
            encodedHeader.writeUInt32LE(234, 1);
            //@ts-ignore protected function
            messaging.decodeHeader(encodedHeader);
        }, /Mismatch in expected length and provided buffer length./);
    }
}

@TestSuite()
export class MessagingSocketClose {
    @Test()
    public alreadyClosed_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            messaging.isClosed = true;
            //@ts-ignore protected function
            messaging.socketClose();
            assert(messaging.isClosed == true);
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {
            //@ts-ignore protected function
            messaging.emitEvent = function(emitters: EventEmitter[], type: EventType, arg: any) {
                assert(emitters)
                assert(type == EventType.CLOSE || type == EventType.ANY);
                assert(arg);
            };
            assert(messaging.isClosed == false);
            //@ts-ignore protected function
            messaging.socketClose();
            assert(messaging.isClosed == true);
        });
    }
}

@TestSuite()
export class MessagingSocketData {
    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {

            let flag = false;
            //@ts-ignore custom signature
            messaging.processInqueue = function() {
                flag = true;
            }
            assert(messaging.incomingQueue.encrypted.length == 0);
            assert(messaging.isBusyIn == 0);
            assert(flag == false);
            //@ts-ignore protected function
            messaging.socketData(Buffer.from(""));
            assert(messaging.incomingQueue.encrypted.length == 1);
            assert(messaging.isBusyIn == 1);
            //@ts-ignore: expected to be changed by custom processInqueue
            assert(flag == true);
        });
    }
}

@TestSuite()
export class MessagingProcessInqueue {
    @Test()
    public not_busy_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(function() {

            let flag = false;
            //@ts-ignore custom signature
            messaging.decryptIncoming = function() {
                flag = true;
            }
            assert(flag == false);
            messaging.isBusyIn = 0;
            //@ts-ignore protected function
            messaging.processInqueue();
            assert(messaging.isBusyIn == 0);
            assert(flag == false);
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            let counter = 0;
            //@ts-ignore custom signature
            messaging.decryptIncoming = function() {
                counter++;
            }
            //@ts-ignore custom signature
            messaging.assembleIncoming = function() {
                counter++;
            }
            //@ts-ignore custom signature
            messaging.dispatchIncoming = function() {
                counter++;
            }
            messaging.isBusyIn = 1;
            //@ts-ignore protected function
            await messaging.processInqueue();
            assert(counter == 2);
        });
    }
}

@TestSuite()
export class MessagingDecryptIncoming {
    @Test()
    public unencrypted() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from(""));

            assert(messaging.incomingQueue.encrypted.length == 1);
            assert(messaging.incomingQueue.decrypted.length == 0);
            //@ts-ignore protected function
            messaging.decryptIncoming();
            assert(messaging.incomingQueue.encrypted.length == 0);
            assert(messaging.incomingQueue.decrypted.length == 1);
        });
    }

    @Test()
    public encrypted_data_not_ready() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            const keyPair = {
                publicKey: Buffer.from(""),
                secretKey: Buffer.from("")
            };

            const outKey = Buffer.alloc(32);
            const outNonce = Buffer.alloc(24);
            const inKey = Buffer.alloc(32);
            const inNonce = Buffer.alloc(24);
            const peerPubKey = Buffer.alloc(32);
            await messaging.setEncrypted(outKey, outNonce, inKey, inNonce, peerPubKey);
            messaging.incomingQueue.encrypted.push(Buffer.from("aaa"));

            assert(messaging.incomingQueue.encrypted.length == 1);
            assert(messaging.incomingQueue.decrypted.length == 0);
            //@ts-ignore protected function
            messaging.decryptIncoming();
            assert(messaging.incomingQueue.encrypted.length == 1);
            assert(messaging.incomingQueue.decrypted.length == 0);
        });
    }
}

@TestSuite()
export class MessagingAssembleIncoming {
    @Test()
    public no_data_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from(""));

            assert(messaging.incomingQueue.encrypted.length == 1);
            assert(messaging.incomingQueue.decrypted.length == 0);
            //@ts-ignore protected function
            messaging.assembleIncoming();
        });
    }

    @Test()
    public not_enough_data() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("1234"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            //@ts-ignore protected function
            messaging.assembleIncoming();
        });
    }

    @Test()
    public bad_version() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();

            // Set custom version
            messaging.incomingQueue.decrypted[0].writeUInt8(244);

            //@ts-ignore protected function
            messaging.assembleIncoming();
        });
    }

    @Test()
    public not_enough_data_extractBuffer() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            messaging.incomingQueue.decrypted[0].writeUInt8(0);

            //@ts-ignore protected function
            messaging.extractBuffer = function() {
                return undefined;
            }

            //@ts-ignore protected function
            messaging.assembleIncoming();
        });
    }

    @Test()
    public bad_stream_decodeHeader() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            messaging.incomingQueue.decrypted[0].writeUInt8(0);

            //@ts-ignore protected function
            messaging.extractBuffer = function() {
                return Buffer.from("");
            }
            //@ts-ignore protected function
            messaging.decodeHeader = function() {
                return undefined;
            }

            //@ts-ignore protected function
            messaging.assembleIncoming();
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            messaging.incomingQueue.decrypted[0].writeUInt8(0);

            //@ts-ignore protected function
            messaging.extractBuffer = function() {
                return Buffer.from("");
            }
            //@ts-ignore protected function
            messaging.decodeHeader = function() {
                messaging.incomingQueue.decrypted.length = 0;
                return [{version: 0, target: "tgt", dataLength: 3, config: false}, Buffer.from("")];
            }

            assert(messaging.incomingQueue.messages.length == 0);
            //@ts-ignore protected function
            messaging.assembleIncoming();
            assert(messaging.incomingQueue.messages.length == 1);
        });
    }
}

@TestSuite()
export class MessagingDispatchIncoming {
    @Test()
    public no_data_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from(""));

            assert(messaging.incomingQueue.messages.length == 0);
            //@ts-ignore protected function
            messaging.dispatchIncoming();
            assert(messaging.incomingQueue.messages.length == 0);
        });
    }

    @Test()
    public dispatchLimit_is_zero() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            messaging.incomingQueue.decrypted[0].writeUInt8(0);

            //@ts-ignore protected function
            messaging.extractBuffer = function() {
                return Buffer.from("");
            }
            //@ts-ignore protected function
            messaging.decodeHeader = function() {
                messaging.incomingQueue.decrypted.length = 0;
                return [{version: 0, target: Buffer.from("tgt"), dataLength: 3, config: false}, Buffer.from("")];
            }

            //@ts-ignore protected function
            messaging.assembleIncoming();
            assert(messaging.incomingQueue.messages.length == 1);
            messaging.dispatchLimit = 0;
            //@ts-ignore protected function
            messaging.dispatchIncoming();
            assert(messaging.incomingQueue.messages.length == 1);
        });
    }

    @Test()
    public dispatchLimit_is_one() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            messaging.incomingQueue.decrypted[0].writeUInt8(0);

            //@ts-ignore protected function
            messaging.extractBuffer = function() {
                return Buffer.from("");
            }
            //@ts-ignore protected function
            messaging.decodeHeader = function() {
                messaging.incomingQueue.decrypted.length = 0;
                return [{version: 0, target: Buffer.from("tgt"), dataLength: 3, config: false}, Buffer.from("")];
            }

            //@ts-ignore protected function
            messaging.assembleIncoming();
            assert(messaging.incomingQueue.messages.length == 1);
            messaging.dispatchLimit = 1;
            //@ts-ignore protected function
            messaging.dispatchIncoming();
            assert(messaging.incomingQueue.messages.length == 0);
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.incomingQueue.encrypted.push(Buffer.from("12345"));
            //@ts-ignore protected function
            messaging.decryptIncoming();
            messaging.incomingQueue.decrypted[0].writeUInt8(0);

            //@ts-ignore protected function
            messaging.extractBuffer = function() {
                return Buffer.from("");
            }
            //@ts-ignore protected function
            messaging.decodeHeader = function() {
                messaging.incomingQueue.decrypted.length = 0;
                return [{version: 0, target: Buffer.from("tgt"), dataLength: 3, config: false}, Buffer.from("")];
            }

            //@ts-ignore protected function
            messaging.assembleIncoming();
            assert(messaging.incomingQueue.messages.length == 1);
            //@ts-ignore protected function
            messaging.dispatchIncoming();
            assert(messaging.incomingQueue.messages.length == 0);
        });
    }
}

@TestSuite()
export class MessagingProcessOutqueue {
    @Test()
    public isBusyOut_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {

            messaging.isBusyOut = 0;

            let counter = 0;
            //@ts-ignore protected function
            messaging.encryptOutgoing = function() {
                counter++;
            }
            //@ts-ignore protected function
            messaging.dispatchOutgoing = function() {
                counter++;
            }
            assert(counter == 0);
            //@ts-ignore protected function
            messaging.processOutqueue();
            assert(counter == 0);
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isBusyOut = 1;

            let encryptFlag = false;
            let dispatchFlag = false;
            //@ts-ignore protected function
            messaging.encryptOutgoing = async function() {
                encryptFlag = true;
                return Promise.resolve(true);
            }
            //@ts-ignore protected function
            messaging.dispatchOutgoing = function() {
                dispatchFlag = true;
            }
            //@ts-ignore protected function
            await messaging.processOutqueue();
            //@ts-ignore expected to be set by custom function
            assert(encryptFlag == true);
            //@ts-ignore expected to be set by custom function
            assert(dispatchFlag == true);
        });
    }
}

@TestSuite()
export class MessagingEncryptOutgoing {
    @Test()
    public unencrypted_successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isOpened = true;
            messaging.isClosed = false;
            const replyStatus = messaging.send(Buffer.alloc(255).fill(255));
            assert(messaging.outgoingQueue.unencrypted.length == 1 + 1);
            assert(messaging.outgoingQueue.encrypted.length == 0);
            //@ts-ignore: protected function
            await messaging.encryptOutgoing();
            assert(messaging.outgoingQueue.unencrypted.length == 0);
            assert(messaging.outgoingQueue.encrypted.length == 2);
        });
    }

    @Test()
    public encrypted_successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isOpened = true;
            messaging.isClosed = false;
            const outKey = Buffer.alloc(32);
            const outNonce = Buffer.alloc(24);
            const inKey = Buffer.alloc(32);
            const inNonce = Buffer.alloc(24);
            const peerPubKey = Buffer.alloc(32);
            await messaging.setEncrypted(outKey, outNonce, inKey, inNonce, peerPubKey);
            const replyStatus = messaging.send(Buffer.alloc(255).fill(255));
            assert(messaging.outgoingQueue.unencrypted.length == 1 + 1);
            assert(messaging.outgoingQueue.encrypted.length == 0);

            //@ts-ignore: protected function
            await messaging.encryptOutgoing();
            assert(messaging.outgoingQueue.unencrypted.length == 0);
            assert(messaging.outgoingQueue.encrypted.length == 2);
        });
    }
}

@TestSuite()
export class MessagingDispatchOutgoing {
    @Test()
    public no_encrypted_data_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            assert(messaging.outgoingQueue.encrypted.length == 0);
            //@ts-ignore: protected function
            await messaging.dispatchOutgoing();
            assert(messaging.outgoingQueue.encrypted.length == 0);
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isOpened = true;
            messaging.isClosed = false;
            const outKey = Buffer.alloc(32);
            const outNonce = Buffer.alloc(24);
            const inKey = Buffer.alloc(32);
            const inNonce = Buffer.alloc(24);
            const peerPubKey = Buffer.alloc(32);
            await messaging.setEncrypted(outKey, outNonce, inKey, inNonce, peerPubKey);
            const replyStatus = messaging.send(Buffer.alloc(255).fill(255));
            //@ts-ignore: protected function
            await messaging.encryptOutgoing();

            let flag = false;
            messaging.socket.send = function() {
                flag = true;
            }
            assert(flag == false);
            assert(messaging.outgoingQueue.encrypted.length == 2);
            //@ts-ignore: protected function
            await messaging.dispatchOutgoing();
            //@ts-ignore: flag expected to be toggled by custom socket send procedure
            assert(flag == true);
            assert(messaging.outgoingQueue.encrypted.length == 0);
        });
    }
}

@TestSuite()
export class MessagingCheckTimeouts {
    @Test()
    public unset_isOpened_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isOpened = false;
            //@ts-ignore: protected function
            messaging.checkTimeouts();
        });
    }

    @Test()
    public set_isClosed_noop() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isClosed = true;
            //@ts-ignore: protected function
            messaging.checkTimeouts();
        });
    }

    @Test()
    public successful_call() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.open();
            assert(messaging.isOpened == true);
            assert(messaging.isClosed == false);
            //@ts-ignore: protected function
            messaging.getTimeoutedPendingMessages = function() {
                let messages: SentMessage[] = [];
                messages.push({
                    timestamp: 0,
                    msgId: Buffer.from("10"),
                    timeout: 0,
                    timeoutStream: 0,
                    replyCounter: 0,
                    stream: false,
                    eventEmitter: new EventEmitter(),
                    isCleared: false,
                });
                return messages;
            }
            messaging.cancelPendingMessage = function(id: Buffer) {
                assert(id.toString() == "10");
            }
            //@ts-ignore: protected function
            messaging.emitEvent = function(emitter: EventEmitter[], type: EventType, timeout: TimeoutEvent) {
                assert(type == EventType.TIMEOUT);
                //@ts-ignore: protected function
                messaging.emitEvent = () => {};  // We need to cancel this because a "close" event would else reach this function and the assert will trigger.
                messaging.close();
            }
            //@ts-ignore: protected function
            messaging.checkTimeouts();
        });
    }
}

@TestSuite()
export class MessagingGetTimeoutedPendingMessages {
    @Test()
    public successful_call_timeout() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isOpened = true;
            messaging.isClosed = false;
            //@ts-ignore: protected function
            messaging.pendingReply["20"] = {
                timestamp: 0,
                msgId: Buffer.from("20"),
                timeout: 1,
                timeoutStream: 0,
                replyCounter: 0,
                stream: false,
                eventEmitter: new EventEmitter()
            };
            //@ts-ignore: protected function
            let data = messaging.getTimeoutedPendingMessages();
            assert(data.length == 1);
        });
    }

    @Test()
    public successful_call_no_timeout() {
        let [socket, _] = CreatePair();
        let messaging = new Messaging(socket);
        assert.doesNotThrow(async function() {
            messaging.isOpened = true;
            messaging.isClosed = false;
            //@ts-ignore: protected function
            messaging.pendingReply["20"] = {
                timestamp: 0,
                msgId: Buffer.from("20"),
                timeout: 0,
                timeoutStream: 0,
                replyCounter: 0,
                stream: false,
                eventEmitter: new EventEmitter()
            };
            //@ts-ignore: protected function
            let data = messaging.getTimeoutedPendingMessages();
            assert(data.length == 0);
        });
    }
}
