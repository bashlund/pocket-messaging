import {Client} from "../../pocket-sockets";
import EventEmitter from "eventemitter3";
import {encrypt, decrypt, randomBytes} from "./Crypto";

import {
    SentMessage,
    Header,
    OutgoingQueue,
    InMessage,
    IncomingQueue,
    RouteEvent,
    ReplyEvent,
    TimeoutEvent,
    ErrorEvent,
    MixedEvent,
    CloseEvent,
    EventType,
} from "./types";

export class Messaging {

    /**
     * Messages sent from here which are expecting replies.
     *
     */
    pendingReply: {[msgId: string]: SentMessage};

    /**
     * Data read on socket and transformed to messages.
     */
    incomingQueue: IncomingQueue;

    /**
     * Messages transformed and sent.
     */
    outgoingQueue: OutgoingQueue;

    /**
     * The general event emitter for incoming messages and socket events.
     * Reply messages are not emitted using this object but are emitted on message specific event emitters.
     */
    eventEmitter: EventEmitter;

    /**
     * The given client socket to communicate with.
     */
    socket: Client;

    /**
     * Set to true if we have opened.
     */
    isOpened: boolean;

    /**
     * Set to true if we have closed.
     */
    isClosed: boolean;

    /**
     * Set to true to have streams encrypted/decrypted
     */
    useEncryption: boolean;

    /**
     * The peer public key used for encryption
     */
    peerPublicKey?: Buffer;

    /**
     * Our public and secret key pair used for encryption.
     */
    keyPair?: {publicKey: Buffer, secretKey: Buffer};

    /**
     * How many messages we allow through.
     * 0 means cork it up
     * -1 means unlimited.
     */
    dispatchLimit: number;

    isBusyOut: number;
    isBusyIn: number;
    instanceId: string;

    constructor(socket: Client) {
        this.socket = socket;
        this.pendingReply = {};
        this.isOpened = false;
        this.isClosed = false;
        this.useEncryption = false;
        this.dispatchLimit = -1;
        this.isBusyOut = 0;
        this.isBusyIn = 0;
        this.instanceId = Buffer.from(randomBytes(8)).toString("hex");
        this.incomingQueue = {
            encrypted: [],
            decrypted: [],
            messages: []
        };
        this.outgoingQueue = {
            unencrypted: [],
            encrypted: []
        };
        this.eventEmitter = new EventEmitter();
    }

    public getInstanceId(): string {
        return this.instanceId;
    }

    public setEncrypted(peerPublicKey?: Buffer, keyPair?: {publicKey: Buffer, secretKey: Buffer}) {
        if (peerPublicKey) {
            this.peerPublicKey = peerPublicKey;
        }
        if (keyPair) {
            this.keyPair = keyPair;
        }

        if (!this.peerPublicKey || !this.keyPair) {
            throw "Missing peerPublicKey and/or keyPair for encryption.";
        }

        this.useEncryption = true;
    }

    public setUnencrypted() {
        this.useEncryption = false;
    }

    /**
     * Remove a stored pending message so that it cannot receive any more replies.
     */
    public cancelPendingMessage(msgId: Buffer) {
        delete this.pendingReply[msgId.toString("hex")];
    }

    /**
     * Get the general event emitter object.
     * This is used to listen for incoming messages
     * and socket events such as close and error.
     */
    public getEventEmitter(): EventEmitter {
        return this.eventEmitter;
    }

    /**
     * Open this Messaging object for communication.
     * Don't open it until you have hooked the event emitter.
     */
    public open() {
        if (this.isOpened || this.isClosed) {
            return;
        }
        this.isOpened = true;
        this.socket.onError(this.socketError);
        this.socket.onClose(this.socketClose);
        this.socket.onData(this.socketData);
        this.checkTimeouts();
    }

    public isOpen(): boolean {
        return this.isOpened && !this.isClosed;
    }

    /**
     * Close this Messaging object and it's socket.
     *
     */
    public close() {
        if (this.isClosed) {
            return;
        }
        this.isClosed = true;
        this.socket.close();
    }

    public cork() {
        this.dispatchLimit = 0;
    }

    public uncork(limit?: number) {
        this.dispatchLimit = limit ?? -1;
    }

    public send(target: Buffer | string, data?: Buffer, timeout?: number, stream?: boolean): EventEmitter | undefined {
        if (!this.isOpened || this.isClosed) {
            return;
        }

        if (typeof target === "string") {
            target = Buffer.from(target);
        }

        data = data ?? Buffer.alloc(0);

        const msgId = this.generateMsgId();

        const expectingReply = typeof timeout === "number" ? (stream ? 2 : 1) : 0;

        if (target.length > 255) {
            throw "target length cannot exceed 255 bytes";
        }

        const header: Header = {
            version: 0,
            target,
            dataLength: data.length,
            msgId,
            config: expectingReply
        };
        const headerBuffer = this.encodeHeader(header);
        this.outgoingQueue.unencrypted.push(headerBuffer);
        this.outgoingQueue.unencrypted.push(data);
        this.isBusyOut++;
        setImmediate(this.processOutqueue);

        if (expectingReply === 0) {
            return undefined;
        }

        const eventEmitter = new EventEmitter();

        this.pendingReply[msgId.toString("hex")] = {
            timestamp: this.getNow(),
            msgId,
            timeout: Number(timeout),
            stream: Boolean(stream),
            eventEmitter,
        };

        return eventEmitter;
    }

    protected getNow(): number {
        return Date.now();
    }

    protected generateMsgId(): Buffer {
        const msgId = Buffer.from(randomBytes(4));
        return msgId;
    }

    protected encodeHeader(header: Header): Buffer {
        if (header.target.length > 255) {
            throw "Target length cannot exceed 255 bytes.";
        }
        if (header.msgId.length !== 4) {
            throw "msgId length must be exactly 4 bytes long.";
        }

        const headerLength = 1 + 4 + 1 + 4 + 1 + header.target.length;
        const totalLength = headerLength + header.dataLength;

        const buffer = Buffer.alloc(headerLength);
        let pos = 0;
        buffer.writeUInt8(pos, header.version);
        pos++;
        buffer.writeUInt32LE(totalLength, pos);
        pos = pos + 4;
        buffer.writeUInt8(header.config, pos);
        pos++;
        header.msgId.copy(buffer, pos);
        pos = pos + header.msgId.length;
        buffer.writeUInt8(header.target.length, pos);
        pos++;
        header.target.copy(buffer, pos);

        return buffer;
    }

    protected decodeHeader(buffer: Buffer): [Header, Buffer] | undefined {
        let pos = 0;
        const version = buffer.readUInt8(pos);
        if (version !== 0) {
            throw "Unexpected version nr. Only supporting version 0.";
        }
        pos++
        const totalLength = buffer.readUInt32LE(pos);
        if (totalLength !== buffer.length) {
            throw "Mismatch in expected length and provided buffer length.";
        }
        pos = pos + 4;

        const config = buffer.readUInt8(pos);
        pos++;
        const msgId = buffer.slice(pos, pos + 4);
        pos = pos + 4;
        const targetLength = buffer.readUInt8(pos);
        pos++;
        const target = buffer.slice(pos, pos + targetLength);
        pos = pos + targetLength;

        const data = buffer.slice(pos);
        const dataLength = data.length;

        const header: Header = {
            version,
            target,
            msgId,
            config,
            dataLength
        };

        return [header, data];
    }

    /**
    * Extract length as single buffer and modify the buffers array in place.
    *
    */
    protected extractBuffer(buffers: Buffer[], length: number): Buffer | undefined {
        let count = 0;
        for (let index=0; index<buffers.length; index++) {
            count = count + buffers[index].length;
        }
        if (count < length) {
            // Not enough data ready.
            return undefined;
        }

        let extracted = Buffer.alloc(0);
        while (extracted.length < length) {
            const bytesNeeded = length - extracted.length;
            const buffer = buffers[0];
            if (buffer.length <= bytesNeeded) {
                // Take the whole buffer and remove it from list
                buffers.shift();
                extracted = Buffer.concat([extracted, buffer]);
            }
            else {
                // Take part of the buffer and modify it in place
                extracted = Buffer.concat([extracted, buffer.slice(0, bytesNeeded)]);
                buffers[0] = buffer.slice(bytesNeeded);
            }
        }

        return extracted;
    }

    protected emitEvent(eventEmitters: EventEmitter[], eventType: EventType, arg?: any) {
        for (let index = 0; index < eventEmitters.length; index++) {
            eventEmitters[index].emit(eventType, arg);
        }
    }

    protected getAllEventEmitters(): EventEmitter[] {
        const eventEmitters: EventEmitter[] = [];
        for (let msgId in this.pendingReply) {
            eventEmitters.push(this.pendingReply[msgId].eventEmitter);
        }
        eventEmitters.push(this.eventEmitter);
        return eventEmitters;
    }

    /**
     * Notify all pending messages and the main emitter about the error.
     *
     */
    protected socketError = (error?: Buffer) => {
        const eventEmitters = this.getAllEventEmitters();

        const errorEvent: ErrorEvent = {
            error
        };
        this.emitEvent(eventEmitters, EventType.ERROR, errorEvent);

        const mixedEvent: MixedEvent = {
            type: EventType.ERROR,
            event: errorEvent
        };
        this.emitEvent(eventEmitters, EventType.MIXED, mixedEvent);
    }

    /**
     * Notify all pending messages about the close.
     */
    protected socketClose = (hadError: boolean) => {
        if (this.isClosed) {
            return;
        }
        this.isClosed = true;
        const eventEmitters = this.getAllEventEmitters();
        const closeEvent: CloseEvent = {
            hadError: Boolean(hadError)
        };
        this.emitEvent(eventEmitters, EventType.CLOSE, closeEvent);
        const mixedEvent: MixedEvent = {
            type: EventType.CLOSE,
            event: closeEvent
        };
        this.emitEvent(eventEmitters, EventType.MIXED, mixedEvent);
    }

    /**
     * Buffer incoming raw data from the socket.
     * Ping decryptIncoming so it can have a go on the new data.
     */
    protected socketData = (data: Buffer) => {
        this.incomingQueue.encrypted.push(data);
        this.isBusyIn++;
        this.processInqueue();
        setImmediate(this.processInqueue);
    }

    protected processInqueue = async () => {
        if (this.isBusyIn <= 0) {
            return;
        }
        this.isBusyIn--;

        await this.decryptIncoming();
        this.assembleIncoming();
        this.dispatchIncoming();
        this.processInqueue();  // In case someone increased the isBusyIn counter
    }

    /**
     * Decrypt buffers in the inqueue and move them to the dispatch queue.
     */
    protected decryptIncoming = async () => {
        if (this.useEncryption) {
            //@ts-chillax
            if (!this.peerPublicKey || !this.keyPair?.secretKey) {
                console.error("Missing crypto configuration");
                return;
            }

            while (this.incomingQueue.encrypted.length > 0) {
                if (this.incomingQueue.encrypted[0].length < 4) {
                    // Not enough data ready
                    return;
                }
                const length = this.incomingQueue.encrypted[0].readUInt32LE(0);

                const chunk = this.extractBuffer(this.incomingQueue.encrypted, length);
                if (!chunk) {
                    // Not enough data ready
                    return;
                }

                // TODO: this we should do in a separate thread
                const decrypted = decrypt(chunk, this.peerPublicKey, this.keyPair.secretKey);
                if (!decrypted) {
                    console.error("Cannot decrypt stream. Closing.");
                    this.close();
                    return;
                }
                this.incomingQueue.decrypted.push(decrypted);
            }
        }
        else {
            // Just move the buffers to the next queue as they are
            const buffers = this.incomingQueue.encrypted.slice();
            this.incomingQueue.encrypted.length = 0;
            this.incomingQueue.decrypted.push(...buffers);
        }
    }

    /**
     * Assemble messages from decrypted data and put to next queue.
     *
     */
    protected assembleIncoming = () => {
        while (this.incomingQueue.decrypted.length > 0) {
            if (this.incomingQueue.decrypted[0].length < 5) {
                // Not enough data ready
                return;
            }

            // Check version byte
            const version = this.incomingQueue.decrypted[0].readUInt8(0);
            if (version !== 0) {
                console.error("Bad stream detected, closing.");
                this.close();
                return;
            }

            const length = this.incomingQueue.decrypted[0].readUInt32LE(1);

            const buffer = this.extractBuffer(this.incomingQueue.decrypted, length);
            if (!buffer) {
                // Not enough data ready
                return;
            }

            const ret = this.decodeHeader(buffer);
            if (!ret) {
                console.error("Bad stream detected, closing.");
                this.close();
                return;
            }
            const [header, data]: [Header, Buffer] = ret;

            const inMessage: InMessage = {
                target: header.target,
                msgId: header.msgId,
                data,
                expectingReply: header.config & 3,  // other config bits are reserved for future use
            };

            this.incomingQueue.messages.push(inMessage);
        }
    };

    /**
     * Dispatch messages on event emitters.
     *
     */
    protected dispatchIncoming = () => {
        while (this.incomingQueue.messages.length > 0) {
            if (this.dispatchLimit === 0) {
                // This is corked
                return;
            }
            else if (this.dispatchLimit > 0) {
                this.dispatchLimit--;
            }
            else {
                // Negative number means no limiting in place
                // Let through
            }

            const inMessage = this.incomingQueue.messages.pop();

            if (inMessage) {
                // Note: target is not necessarily a msg ID,
                // but we check if it is.
                const targetMsgId = inMessage.target.toString("hex");
                const pendingReply = this.pendingReply[targetMsgId];

                if (pendingReply) {
                    if (pendingReply.stream) {
                        // Expecting many replies, update timeout activity timestamp.
                        pendingReply.timestamp = this.getNow();
                    }
                    else {
                        // Remove pending message if only single message is expected
                        this.cancelPendingMessage(pendingReply.msgId);
                    }

                    // Dispatch reply on message specific event emitter
                    const replyEvent: ReplyEvent = {
                        toMsgId: inMessage.target,
                        fromMsgId: inMessage.msgId,
                        data: inMessage.data,
                        expectingReply: inMessage.expectingReply
                    };
                    this.emitEvent([pendingReply.eventEmitter],
                                   EventType.REPLY, replyEvent);
                    const mixedEvent: MixedEvent = {
                        type: EventType.REPLY,
                        event: replyEvent
                    };
                    this.emitEvent([pendingReply.eventEmitter],
                                   EventType.MIXED, mixedEvent);
                }
                else {
                    // This is not a reply message (or the message was cancelled).
                    // Dispatch on main event emitter.
                    // Note that if this is a reply event on a removed pending
                    // message then the reply will get routed on the main
                    // event emitter (but likely then ignored).
                    const routeEvent: RouteEvent = {
                        target: inMessage.target.toString(),
                        fromMsgId: inMessage.msgId,
                        data: inMessage.data,
                        expectingReply: inMessage.expectingReply
                    };
                    this.emitEvent([this.eventEmitter],
                                   EventType.ROUTE, routeEvent);
                }
            }
        }
    }

    protected processOutqueue = async () => {
        if (this.isBusyOut <= 0) {
            return;
        }
        this.isBusyOut--;
        await this.encryptOutgoing();
        this.dispatchOutgoing();
        this.processOutqueue();  // In case isBusyOut counter got increased
    }

    /**
     * Encrypt and move buffer (or just move buffers if not using encryption) to the next out queue.
     */
    protected encryptOutgoing = async () => {
        if (this.useEncryption) {
            //@ts-chillax
            if (!this.keyPair?.secretKey || !this.peerPublicKey) {
                console.error("Crypto malconfigured");
                return;
            }
            while (this.outgoingQueue.unencrypted.length > 0) {
                const chunk = this.outgoingQueue.unencrypted.shift();
                //@ts-chillax
                if (!chunk) {
                    continue;
                }
                // TODO: here we should use another thread to do the heavy work.
                const encrypted = encrypt(chunk, this.peerPublicKey, this.keyPair.secretKey);
                this.outgoingQueue.encrypted.push(encrypted);
            }
        }
        else {
            const buffers = this.outgoingQueue.unencrypted.slice();
            this.outgoingQueue.unencrypted.length = 0;
            this.outgoingQueue.encrypted.push(...buffers);
        }
    }

    protected dispatchOutgoing = () => {
        const buffers = this.outgoingQueue.encrypted.slice();
        this.outgoingQueue.encrypted.length = 0;
        for (let index=0; index<buffers.length; index++) {
            this.socket.send(buffers[index]);
        }
    }

    /**
     * Check every pending message to see which have timeouted.
     *
     */
    protected checkTimeouts = () => {
        if (!this.isOpened || this.isClosed) {
            return;
        }

        const timeouted: SentMessage[] = this.getTimeoutedPendingMessages();

        for (let index=0; index<timeouted.length;index++) {
            const sentMessage = timeouted[index];
            this.cancelPendingMessage(sentMessage.msgId);
        }

        for (let index=0; index<timeouted.length;index++) {
            const sentMessage = timeouted[index];
            const timeoutEvent: TimeoutEvent = {
            };
            this.emitEvent([sentMessage.eventEmitter],
                           EventType.TIMEOUT, timeoutEvent);
        }

        setTimeout(this.checkTimeouts, 500);
    }

    protected getTimeoutedPendingMessages(): SentMessage[] {
        const timeouted: SentMessage[] = [];
        const now = this.getNow();
        for (let msgId in this.pendingReply) {
            const sentMessage = this.pendingReply[msgId];
            if (sentMessage.timeout && now > sentMessage.timestamp + sentMessage.timeout) {
                timeouted.push(sentMessage);
            }
        }
        return timeouted;
    }
}

/**
* Mimicking the async/await once function from the nodejs events module.
* Because EventEmitter3 module doesn't seem to support the async/await promise feature of nodejs events once() function.
*/
export function once(eventEmitter: EventEmitter, eventName: string | symbol): Promise<any> {
    return new Promise( (accept, reject) => {
        try {
            eventEmitter.once(eventName, accept);
        }
        catch(e) {
            reject(e);
        }
    });
}
