import EventEmitter from "eventemitter3";

export type SentMessage = {
    timestamp: number,
    msgId: Buffer,
    timeout: number,
    stream: boolean,
    eventEmitter: EventEmitter,
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

export type MixedEvent = {
    type: string;
    event: ReplyEvent | TimeoutEvent | CloseEvent | ErrorEvent
};

export type CloseEvent = {
    hadError: boolean
};
