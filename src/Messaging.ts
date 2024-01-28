import {ClientInterface} from "pocket-sockets";
import EventEmitter from "eventemitter3";
import crypto from "crypto";  // Only used for synchronous randomBytes.

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
    AnyEvent,
    CloseEvent,
    EventType,
    MESSAGE_MAX_BYTES,
    SendReturn,
    ExpectingReply,
    DEFAULT_PING_INTERVAL,
} from "./types";

import {
    PocketConsole,
} from "pocket-console";

let console = PocketConsole({module: "Messaging"});

export class Messaging {

    /**
     * Messages sent from here which are expecting replies.
     *
     */
    protected pendingReply: {[msgId: string]: SentMessage};

    /**
     * Data read on socket and transformed to messages.
     */
    protected incomingQueue: IncomingQueue;

    /**
     * Messages transformed and sent.
     */
    protected outgoingQueue: OutgoingQueue;

    /**
     * The general event emitter for incoming messages and socket events.
     * Reply messages are not emitted using this object but are emitted on message specific event emitters.
     */
    protected eventEmitter: EventEmitter;

    /**
     * The given client socket to communicate with.
     */
    protected socket: ClientInterface;

    /**
     * Set to true if we have opened.
     */
    protected _isOpened: boolean;

    /**
     * Set to true if we have closed.
     */
    protected _isClosed: boolean;

    /** ID of the timeout in use for ping. */
    protected pingTimeout: ReturnType<typeof setTimeout> | undefined;

    /** Milliseconds to wait between each ping. */
    protected pingInterval: number;

    /**
     * How many messages we allow through.
     * 0 means cork it up
     * -1 means unlimited.
     */
    protected dispatchLimit: number;

    protected isBusyOut: number;
    protected isBusyIn: number;
    protected instanceId: string;

    /**
     * @param the underlying socket to use.
     * @param pingInterval in milliseconds, set to send frequent pings on the socket to detect silent disconnects.
     */
    constructor(socket: ClientInterface, pingInterval?: number) {
        this.socket = socket;
        this.pendingReply = {};
        this._isOpened = false;
        this._isClosed = false;
        this.pingInterval = pingInterval ?? DEFAULT_PING_INTERVAL;
        this.dispatchLimit = -1;
        this.isBusyOut = 0;
        this.isBusyIn = 0;
        this.instanceId = Buffer.from(crypto.randomBytes(8)).toString("hex");
        this.incomingQueue = {
            chunks: [],
            messages: []
        };
        this.outgoingQueue = {
            chunks: [],
        };
        this.eventEmitter = new EventEmitter();
        this.socket.onError(this.socketError);
        this.socket.onClose(this.socketClose);
    }

    public getInstanceId(): string {
        return this.instanceId;
    }

    /**
     * Remove a stored pending message so that it cannot receive any more replies.
     */
    public cancelPendingMessage = (msgId: Buffer) => {
        delete this.pendingReply[msgId.toString("hex")];
    }

    /**
     * See if a specific msgId is pending a reply.
     * @param msgId the ID of the message to check if it is pending a reply.
     * @returns true if message identified by msgId is pending a reply.
     */
    public isMessagePending = (msgId: Buffer): boolean => {
        if (this.pendingReply[msgId.toString("hex")]) {
            return true;
        }
        return false;
    }

    /**
     * This pauses all timeouts for a message until the next message arrives then timeouts are re-activated (if set initially ofc).
     * This could be useful when expecting a never ending stream of messages where chunks could be time apart.
     */
    public clearTimeout = (msgId: Buffer) => {
        const sentMessage = this.pendingReply[msgId.toString("hex")];
        if (sentMessage) {
            sentMessage.isCleared = true;
        }
    };

    /**
     * Get the general event emitter object.
     * This is used to listen for incoming messages
     * and socket events such as close and error.
     */
    public getEventEmitter(): EventEmitter {
        return this.eventEmitter;
    }

    /**
     * Open this Messaging for inbound data.
     *
     * Do not open it until you have hooked the event emitter
     * to not loose any incoming data.
     *
     * It is technically allowed to send data before opening,
     * but the Messaging should be opened very shortly after
     * sending so that replies can come through and so that
     * timeouts are processed properly.
     */
    public open() {
        if (this._isOpened || this._isClosed) {
            return;
        }

        this._isOpened = true;

        this.socket.onData(this.socketData);

        this.checkTimeouts();

        if (this.pingInterval > 0) {
            this.enablePing(this.pingInterval);
        }
    }

    public isOpen(): boolean {
        return this._isOpened && !this._isClosed;
    }

    public isOpened(): boolean {
        return this._isOpened;
    }

    public isClosed(): boolean {
        return this._isClosed;
    }

    /**
     * Close this Messaging object and it's socket.
     *
     */
    public close() {
        if (this._isClosed) {
            return;
        }
        // Note the socket was already open when it was passed into Messaging.
        this.socket?.close();
    }

    public cork() {
        this.dispatchLimit = 0;
    }

    public uncork(limit?: number) {
        this.dispatchLimit = limit ?? -1;
    }

    /**
     * Send message to remote.
     *
     * The returned EventEmitter can be hooked as eventEmitter.on("reply", fn) or
     *  const data: ReplyEvent = await once(eventEmitter, "reply");
     *  Other events are "close" (CloseEvent) and "any" which trigger both for "reply", "close" and "error" (ErrorEvent). There is also "timeout" (TimeoutEvent).
     *
     * A timeouted message is removed from memory and a TIMEOUT is emitted.
     *
     * @param target: Buffer | string either set as routing target as string, or as message ID in reply to (as buffer).
     *  The receiving Messaging instance will check if target matches a msg ID which is waiting for a reply and in such case the message till be emitted on that EventEmitter,
     *  or else it will pass it to the router to see if it matches some route.
     * @param data: Buffer of data to be sent. Note that data cannot exceed MESSAGE_MAX_BYTES (64 KiB).
     * @param timeout milliseconds to wait for the first reply (defaults to -1)
     *     -1 means we are not expecting a reply
     *     0 or greater means that we are expecting a reply, 0 means wait forever
     * @param stream set to true if expecting multiple replies (defaults to false)
     *     This requires that timeout is set to 0 or greater
     * @param timeoutStream milliseconds to wait for secondary replies, 0 means forever (default).
     *     Only relevant if expecting multiple replies (stream = true).
     * @return SendReturn | undefined
     *     SendReturn.msgId is always set
     *     SendReturn.eventEmitter property is set if expecting reply
     *     undefined is returned as a silent error when the Messaging is closed and data cannot be sent again on this Messaging instance.
     * @throws on malformed input
     */
    public send(target: Buffer | string, data?: Buffer, timeout: number = -1, stream: boolean = false, timeoutStream: number = 0): SendReturn | undefined {
        if (this._isClosed) {
            console.debug("Messaging is closed, cannot send");
            return undefined;
        }

        if (typeof target === "string") {
            target = Buffer.from(target);
        }

        data = data ?? Buffer.alloc(0);

        if (data.length > MESSAGE_MAX_BYTES) {
            throw new Error(`Data chunk to send cannot exceed ${MESSAGE_MAX_BYTES} bytes. Trying to send ${data.length} bytes`);
        }

        if (target.length > 255) {
            throw new Error("target length cannot exceed 255 bytes");
        }

        const msgId = this.generateMsgId();

        const expectingReply = timeout > -1 ?
            (stream ? ExpectingReply.MULTIPLE : ExpectingReply.SINGLE) : ExpectingReply.NONE;

        const header: Header = {
            version: 0,
            target,
            dataLength: data.length,
            msgId,
            config: expectingReply
        };
        const headerBuffer = this.encodeHeader(header);
        this.outgoingQueue.chunks.push(headerBuffer);
        this.outgoingQueue.chunks.push(data);
        this.isBusyOut++;
        setImmediate(this.processOutqueue);

        if (expectingReply === ExpectingReply.NONE) {
            return {msgId};
        }

        const eventEmitter = new EventEmitter();

        this.pendingReply[msgId.toString("hex")] = {
            timestamp: this.getNow(),
            msgId,
            timeout: timeout,
            stream: Boolean(stream),
            eventEmitter,
            timeoutStream: timeoutStream,
            replyCounter: 0,
            isCleared: false,
        };

        return {eventEmitter, msgId};
    }

    /**
     * Enable to send frequent pings on the socket.
     * This will help to detect silent disconnects.
     * @param pingInterval how many milliseconds to wait between each ping.
     * Default is 10000 (10 sec). 0 means disabled.
     */
    public enablePing(pingInterval: number = 10000) {
        if (this._isClosed) {
            return;
        }

        this.disablePing();

        this.pingInterval = pingInterval;

        if (this.pingInterval > 0) {
            this.pingTimeout = setTimeout( this.sendPing, this.pingInterval );
        }
    }

    public disablePing() {
        if (this.pingTimeout) {
            clearTimeout(this.pingTimeout);
            this.pingTimeout = undefined;
        }
    }

    /**
     * @returns the underlaying socket client.
     */
    public getClient(): ClientInterface {
        return this.socket;
    }

    protected getNow(): number {
        return Date.now();
    }

    protected generateMsgId(): Buffer {
        const msgId = Buffer.from(crypto.randomBytes(4));
        return msgId;
    }

    protected encodeHeader(header: Header): Buffer {
        if (header.target.length > 255) {
            throw "Target length cannot exceed 255 bytes";
        }
        if (header.msgId.length !== 4) {
            throw "msgId length must be exactly 4 bytes long";
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
            throw "Unexpected version nr, only supporting version 0";
        }
        pos++
        const totalLength = buffer.readUInt32LE(pos);
        if (totalLength !== buffer.length) {
            throw "Mismatch in expected length and provided buffer length";
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
    protected socketError = (error: string) => {
        const eventEmitters = this.getAllEventEmitters();

        const errorEvent: ErrorEvent = {
            error
        };
        this.emitEvent(eventEmitters, EventType.ERROR, errorEvent);

        const anyEvent: AnyEvent = {
            type: EventType.ERROR,
            event: errorEvent
        };
        this.emitEvent(eventEmitters, EventType.ANY, anyEvent);
    }

    /**
     * Notify all pending messages about the close.
     */
    protected socketClose = (hadError: boolean) => {
        if (this._isClosed) {
            return;
        }
        this._isClosed = true;

        this.disablePing();

        const eventEmitters = this.getAllEventEmitters();
        this.pendingReply = {};  // Remove all from memory
        const closeEvent: CloseEvent = {
            hadError: Boolean(hadError)
        };
        this.emitEvent(eventEmitters, EventType.CLOSE, closeEvent);
        const anyEvent: AnyEvent = {
            type: EventType.CLOSE,
            event: closeEvent
        };
        this.emitEvent(eventEmitters, EventType.ANY, anyEvent);
    }

    /**
     * Send a ping to remote to force a disconnect event in the case
     * the socket has silently closed.
     * There is no reply expected on the ping.
     */
    protected sendPing = () => {
        if (this._isClosed) {
            return;
        }

        if (this._isOpened) {
            // Send empty message with an un-routable target.
            this.send(Buffer.from([0]));
        }

        if (this.pingInterval > 0) {
            this.pingTimeout = setTimeout( this.sendPing, this.pingInterval );
        }
    }

    /**
     * Buffer incoming raw data from the socket and process it.
     */
    protected socketData = (data: Buffer | string) => {
        if (Buffer.isBuffer(data)) {
            this.incomingQueue.chunks.push(data);
            this.isBusyIn++;
            this.processInqueue();
        }
        else {
            throw new Error("Messaging does not work with text data");
        }
    }

    protected processInqueue = async () => {
        if (this.isBusyIn <= 0) {
            return;
        }

        this.isBusyIn--;

        if (!this.assembleIncoming()) {
            // Bad stream, close.
            this.close();
            return;
        }

        this.dispatchIncoming();
        this.processInqueue();  // In case someone increased the isBusyIn counter
    }

    /**
     * Assemble messages from decrypted data and put to next queue.
     *
     */
    protected assembleIncoming = (): boolean => {
        while (this.incomingQueue.chunks.length > 0) {
            if (this.incomingQueue.chunks[0].length < 5) {
                // Not enough data ready, see if we can collapse
                if (this.incomingQueue.chunks.length > 1) {
                    const buf = this.incomingQueue.chunks.shift();
                    if (buf) {
                        this.incomingQueue.chunks[0] = Buffer.concat([buf, this.incomingQueue.chunks[0]]);
                    }
                    continue;
                }
                return true;
            }

            // Check version byte
            const version = this.incomingQueue.chunks[0].readUInt8(0);
            if (version !== 0) {
                this.incomingQueue.chunks.length = 0;
                console.error("Bad stream detected reading version byte.");
                return false;
            }

            const length = this.incomingQueue.chunks[0].readUInt32LE(1);

            const buffer = this.extractBuffer(this.incomingQueue.chunks, length);
            if (!buffer) {
                // Not enough data ready
                return true;
            }

            const ret = this.decodeHeader(buffer);
            if (!ret) {
                this.incomingQueue.chunks.length = 0;
                console.error("Bad stream detected in header.");
                return false;
            }
            const [header, data]: [Header, Buffer] = ret;

            const inMessage: InMessage = {
                target: header.target,
                msgId: header.msgId,
                data,
                expectingReply: header.config & (ExpectingReply.SINGLE + ExpectingReply.MULTIPLE),  // other config bits are reserved for future use
            };

            this.incomingQueue.messages.push(inMessage);
        }
        return true;
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

            const inMessage = this.incomingQueue.messages.shift();

            if (inMessage) {
                // Note: target is not necessarily a msg ID,
                // but we check if it is.
                const targetMsgId = inMessage.target.toString("hex");
                const pendingReply = this.pendingReply[targetMsgId];

                if (pendingReply) {
                    pendingReply.replyCounter++;
                    pendingReply.isCleared = false;
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
                    const anyEvent: AnyEvent = {
                        type: EventType.REPLY,
                        event: replyEvent
                    };
                    this.emitEvent([pendingReply.eventEmitter],
                                   EventType.ANY, anyEvent);
                }
                else {
                    // This is not a reply message (or the message was cancelled).
                    // Dispatch on main event emitter.
                    // Do alphanumric check on target string. A-Z, a-z, 0-9, ._-
                    if (inMessage.target.some( char => {
                        if (char >= 49 && char <= 57) {
                            return false;
                        }
                        if (char >= 65 && char <= 90) {
                            return false;
                        }
                        if (char >= 97 && char <= 122) {
                            return false;
                        }
                        if ([45, 46, 95].includes(char)) {
                            return false;
                        }
                        return true; // non alpha-numeric found
                        })) {
                        // Non alphanumeric found
                        // Ignore this message
                        return;
                    }
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

    protected processOutqueue = () => {
        if (this.isBusyOut <= 0) {
            return;
        }
        this.isBusyOut--;
        this.dispatchOutgoing();
        this.processOutqueue();  // In case isBusyOut counter got increased
    }

    protected dispatchOutgoing = () => {
        const buffers = this.outgoingQueue.chunks.slice();
        this.outgoingQueue.chunks.length = 0;
        for (let index=0; index<buffers.length; index++) {
            this.socket.send(buffers[index]);
        }
    }

    /**
     * Check every pending message to see which have timeouted.
     *
     */
    protected checkTimeouts = () => {
        if (!this._isOpened || this._isClosed) {
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
            const anyEvent: AnyEvent = {
                type: EventType.TIMEOUT,
                event: timeoutEvent
            };
            this.emitEvent([sentMessage.eventEmitter],
                           EventType.ANY, anyEvent);
        }

        setTimeout(this.checkTimeouts, 500);
    }

    protected getTimeoutedPendingMessages(): SentMessage[] {
        const timeouted: SentMessage[] = [];
        const now = this.getNow();
        for (let msgId in this.pendingReply) {
            const sentMessage = this.pendingReply[msgId];
            if (sentMessage.isCleared) {
                continue;
            }
            if (sentMessage.replyCounter === 0) {
                if (sentMessage.timeout > 0 && now > sentMessage.timestamp + sentMessage.timeout) {
                    timeouted.push(sentMessage);
                }
            }
            else {
                if (sentMessage.timeoutStream && now > sentMessage.timestamp + sentMessage.timeoutStream) {
                    timeouted.push(sentMessage);
                }
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
    return new Promise( (resolve, reject) => {
        try {
            eventEmitter.once(eventName, resolve);
        }
        catch(e) {
            reject(e);
        }
    });
}
