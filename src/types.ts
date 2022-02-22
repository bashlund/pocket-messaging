import EventEmitter from "eventemitter3";

/**
 * A single message cannot exceed 65535 bytes in total.
 */
export const MESSAGE_MAX_BYTES = 65535;

export type SendReturn = {
    eventEmitter?: EventEmitter,
    msgId: Buffer,
};

export type SentMessage = {
    timestamp: number,
    msgId: Buffer,
    timeout: number,
    stream: boolean,
    timeoutStream: number,
    eventEmitter: EventEmitter,
    replyCounter: number,
    isCleared: boolean,  // If true then all timeouts on this message are paused until next message arrives
};

export enum ExpectingReply {
    NONE = 0,
    SINGLE = 1,
    MULTIPLE = 2,
};

/**
 * Bytes:
 * 0 uint8 header version, must be 0
 * 1-4 uint32le total length of message including version byte above
 * 5 uint8 config byte, used for expectingReply flags
 * 6-9 4 bytes msg ID
 * 10 uint8 length of target value
 * 10 x bytes of target value
 * 10+x data bytes
 */
export type Header = {
    version: number,  // always 0
    target: Buffer,
    msgId: Buffer,
    dataLength: number,

    /**
     * Only bit 0+1 are used to signal expectingReply
     */
    config: number
};

export type OutgoingQueue = {
    unencrypted: Buffer[],
    encrypted: Buffer[]
};

export type InMessage = {
    target: Buffer,
    msgId: Buffer,
    data: Buffer,

    /**
     * 0 no reply expected
     * 1 one reply expected
     * 2 multiple replies expected
     */
    expectingReply: number
};

export type IncomingQueue = {
    encrypted: Buffer[],
    decrypted: Buffer[],
    messages: InMessage[]
};

export type RouteEvent = {
    target: string,
    fromMsgId: Buffer,
    data: Buffer,
    expectingReply: number
};

export type ReplyEvent = {
    toMsgId: Buffer,
    fromMsgId: Buffer,
    data: Buffer,
    expectingReply: number
};

export type TimeoutEvent = {
};

export type ErrorEvent = {
    error?: Buffer
};

export type AnyEvent = {
    type: EventType;
    event: ReplyEvent | TimeoutEvent | CloseEvent | ErrorEvent
};

export type CloseEvent = {
    hadError: boolean
};

export enum EventType {
    /**
     * Data event only emitted on main event emitter on new
     * incoming messages (which are not reply messages).
     */
    ROUTE = "route",

    /**
     * Data event only emitted on message specific event emitters as
     * replies on sent message.
     */
    REPLY = "reply",

    /**
     * Socket error event emitted on all event emitters including main.
     */
    ERROR = "error",

    /**
     * Socket close event emitted on all event emitters including main.
     */
    CLOSE = "close",

    /**
     * Message reply timeout event emitted on message specific event emitters
     * who are awaiting replies on sent message.
     */
    TIMEOUT = "timeout",

    /**
     * Any event emitted on message specific event emitters for the events:
     * REPLY,
     * ERROR,
     * CLOSE,
     * TIMEOUT
     * This is useful for having a catch-all event handler when waiting on replies.
     */
    ANY = "any",
}

export type HandshakeResult = {
    peerLongtermPk: Buffer,
    clientToServerKey: Buffer,
    clientNonce: Buffer,
    serverToClientKey: Buffer,
    serverNonce: Buffer,
    peerData: Buffer,
};
