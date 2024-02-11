import EventEmitter from "eventemitter3";

import {
    SocketFactoryConfig,
    SocketFactoryStats,
    SocketFactoryInterface,
    ClientInterface,
} from "pocket-sockets";

import {
    Messaging,
} from "./Messaging";

import {EVENTS as SOCKETFACTORY_EVENTS} from "pocket-sockets";

export const DEFAULT_PING_INTERVAL = 10000;  // Milliseconds.

/** Msg ID length in bytes. */
export const MSG_ID_LENGTH = 4;

export const PING_ROUTE = "_ping";

/**
 * A single message cannot exceed 67 KiB in total for its payload.
 *
 * 67 KiB allows the sender to send a payload of 64 KiB with plenty
 * of space left for its overhead, and 64 KiB is typically a
 * fitting payload to deal with when reading/storing data.
 *
 * Actual data sent comes with some bytes added overhead.
 */
export const MESSAGE_MAX_BYTES = 67 * 1024;

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
}

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
    chunks: Buffer[],
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
    chunks: Buffer[],
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

export type TimeoutEvent = Record<string, never>;  // Fancy speak for empty object.

export type ErrorEvent = {
    error: string,
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
    longtermPk: Buffer,         // The public key which was used to handshake
    peerLongtermPk: Buffer,     // The handshaked longterm public key of the peer
    clientToServerKey: Buffer,  // box key
    clientNonce: Buffer,        // box nonce
    serverToClientKey: Buffer,  // box key
    serverNonce: Buffer,        // box nonce
    peerData: Buffer,           // arbitrary data provided by peer
};

export type KeyPair = {
    publicKey: Buffer,
    secretKey: Buffer,
};

export type ClientValidatorFunctionInterface = (clientLongTermPk: Buffer) => boolean;

export type PeerDataGeneratorFunctionInterface = (isServer: boolean) => Buffer;

export type HandshakeFactoryConfig = {
    socketFactoryConfig: SocketFactoryConfig,

    socketFactoryStats?: SocketFactoryStats,

    /** The keypair to use in the cryptographic handshake. */
    keyPair: KeyPair,

    /** The discriminator which must match the peer's discriminator when handshaking. */
    discriminator: Buffer,

    /**
     * Arbitrary data sent to the other peer.
     * If a function then call it to get the peerData buffer.
     */
    peerData?: Buffer | PeerDataGeneratorFunctionInterface,

    /** If connecting as client the public key of the server must be set. */
    serverPublicKey?: Buffer,

    /**
     * If opening a server we can discriminate on peers public keys in the handshake.
     * If set as array the client public key must be in the array to accept to client.
     * If set as function the function must return boolean true to accept the client.
     * If not set (undefined) then all clients are accepted.
     * */
    allowedClients?: Buffer[] | ClientValidatorFunctionInterface;

    /** If set, the maximum no of connections each cryptographically handshaked publicKey is allowed. */
    maxConnectionsPerClient?: number,

    /**
     * If set, the maximum no of connections per connected client pair.
     * This is useful for peer-to-peer clients who both have client and server sockets
     * and we only desire a single connection between the client pair.
     * When setting maxConnectionsPerClient=1 there can still be two connections open,
     * but when setting maxConnectionsPerClientPair=1 we can cap the no of connectio to one per pair of clients.
     */
    maxConnectionsPerClientPair?: number,

    /**
     * If set > 0 then the Messaging instances will be configured to
     * frequently send pings to detect silent disconnects of the underlying socket.
     * Unit is milliseconds.
     */
    pingInterval?: number,
};

/**
 * Extend EVENTS from SocketFactory.
 * Add event HANDSHAKE_ERROR with the callback signature HandshakeErrorCallback.
 * Add "HANDSHAKE_ERROR" to ERROR.subEvents.
 */
export const EVENTS = {
    ...SOCKETFACTORY_EVENTS,
    ERROR: {
        ...SOCKETFACTORY_EVENTS.ERROR,
        subEvents: [...SOCKETFACTORY_EVENTS.ERROR.subEvents, "HANDSHAKE_ERROR"],
    },
    HANDSHAKE: {
        name: "HANDSHAKE",
    },
    HANDSHAKE_ERROR: {
        name: "HANDSHAKE_ERROR",
    },
    CLIENT_REFUSE: {
        ...SOCKETFACTORY_EVENTS.CLIENT_REFUSE,
        reason: {
            ...SOCKETFACTORY_EVENTS.CLIENT_REFUSE.reason,
            PUBLICKEY_OVERFLOW: "PUBLICKEY_OVERFLOW",
        }
    },
};

/**
 * Event emitted when client is successfully handshaked and setup for encryption.
 * Note that the returned Messaging object first needs to be .open()'d to be ready for communication.
 */
export type HandshakeCallback = (e: {messaging: Messaging, isServer: boolean, handshakeResult: HandshakeResult}) => void;

/** Event emitted when client could not handshake. */
export type HandshakeErrorCallback = (e: {error: Error, client: ClientInterface}) => void;

export interface HandshakeFactoryInterface extends SocketFactoryInterface {
    getHandshakeFactoryConfig(): HandshakeFactoryConfig;
    onHandshakeError(callback: HandshakeErrorCallback): void;
    onHandshake(callback: HandshakeCallback): void;
}
