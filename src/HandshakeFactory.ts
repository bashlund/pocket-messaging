import {
    SocketFactory,
    Client,
    ConnectCallback,
    ClientRefuseCallback,
} from "pocket-sockets";

import {EVENTS as SOCKETFACTORY_EVENTS} from "pocket-sockets";

import {
    HandshakeFactoryConfig,
    HandshakeResult,
} from "./types";

import {
    Messaging,
} from "./Messaging";

import {
    HandshakeAsServer,
    HandshakeAsClient,
} from "./Handshake";

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
export type HandshakeErrorCallback = (e: {error: Error, client: Client}) => void;

/**
 * This class extends the SocketFactory with handshake capabilties.
 * The SocketFactory EVENTS objects is redeclared here and extended.
 */
export class HandshakeFactory extends SocketFactory {
    protected handshakeFactoryConfig: HandshakeFactoryConfig;

    constructor(handshakeFactoryConfig: HandshakeFactoryConfig) {
        super(handshakeFactoryConfig.socketFactoryConfig, handshakeFactoryConfig.socketFactoryStats);
        this.handshakeFactoryConfig = handshakeFactoryConfig;
    }

    /** Override from parent. */
    protected checkConnectionsOverflow(address: string, isServer: boolean = false): boolean {
        if (super.checkConnectionsOverflow(address, isServer)) {
            return true;
        }

        if (!isServer) {
            if (this.handshakeFactoryConfig.maxConnectionsPerClientPair !== undefined) {
                const pair = [this.handshakeFactoryConfig.serverPublicKey?.toString("hex"),
                    this.handshakeFactoryConfig.keyPair.publicKey.toString("hex")];
                pair.sort();
                const pairKey = pair.join(":");
                const clientPairCount = this.readCounter(pairKey);
                if (clientPairCount >= this.handshakeFactoryConfig.maxConnectionsPerClientPair) {
                    return true;
                }
            }
        }

        return false;
    }

    protected handleOnConnect: ConnectCallback = async (e) => {
        try {
            const messaging = new Messaging(e.client);
            let handshakeResult: HandshakeResult;
            let peerData: Buffer | undefined;
            if (typeof this.handshakeFactoryConfig.peerData === "function") {
                peerData = this.handshakeFactoryConfig.peerData(e.isServer);
            }
            else {
                peerData = this.handshakeFactoryConfig.peerData;
            }
            if (e.isServer) {
                handshakeResult = await HandshakeAsServer(e.client, this.handshakeFactoryConfig.keyPair.secretKey, this.handshakeFactoryConfig.keyPair.publicKey, this.handshakeFactoryConfig.discriminator, this.handshakeFactoryConfig.allowedClients, peerData);
                await messaging.setEncrypted(handshakeResult.serverToClientKey, handshakeResult.serverNonce, handshakeResult.clientToServerKey, handshakeResult.clientNonce, handshakeResult.peerLongtermPk);
            }
            else {
                if (!this.handshakeFactoryConfig.serverPublicKey) {
                    e.client.close();
                    return;
                }
                handshakeResult = await HandshakeAsClient(e.client, this.handshakeFactoryConfig.keyPair.secretKey, this.handshakeFactoryConfig.keyPair.publicKey, this.handshakeFactoryConfig.serverPublicKey, this.handshakeFactoryConfig.discriminator, peerData);
                await messaging.setEncrypted(handshakeResult.clientToServerKey, handshakeResult.clientNonce, handshakeResult.serverToClientKey, handshakeResult.serverNonce, handshakeResult.peerLongtermPk);
            }
            if (!handshakeResult) {
                return;
            }

            const publicKeyStr = handshakeResult.peerLongtermPk.toString("hex");
            if (this.checkClientsOverflow(publicKeyStr)) {
                messaging.close();
                this.triggerEvent(EVENTS.CLIENT_REFUSE.name,
                                  {reason: EVENTS.CLIENT_REFUSE.reason.PUBLICKEY_OVERFLOW, key: handshakeResult.peerLongtermPk});
                return;
            }
            this.increaseClientsCounter(publicKeyStr);
            e.client.onClose( () => {
                this.decreaseClientsCounter(publicKeyStr);
            });

            this.triggerEvent(EVENTS.HANDSHAKE.name, {messaging, isServer: e.isServer, handshakeResult});
        }
        catch(error) {
            if (typeof error === "string") {
                error = new Error(error);
            }
            this.triggerEvent(EVENTS.HANDSHAKE_ERROR.name, {error, client: e.client});
            this.triggerEvent(EVENTS.ERROR.name, {eventName: EVENTS.HANDSHAKE_ERROR, e: {error, client: e.client}});
            e.client.close();
        }
    }

    public init() {
        this.onConnect(this.handleOnConnect);
        super.init();
    }

    public getHandshakeFactoryConfig(): HandshakeFactoryConfig {
        return this.handshakeFactoryConfig;
    }

    /**
     * Increase the counter connections per client public key.
     */
    protected increaseClientsCounter(peerPublicKey: string) {
        this.increaseCounter(peerPublicKey);

        const pair = [peerPublicKey, this.handshakeFactoryConfig.keyPair.publicKey.toString("hex")];
        pair.sort();
        const pairKey = pair.join(":");
        this.increaseCounter(pairKey);
    }

    protected decreaseClientsCounter(peerPublicKey: string) {
        this.decreaseCounter(peerPublicKey);

        const pair = [peerPublicKey, this.handshakeFactoryConfig.keyPair.publicKey.toString("hex")];
        pair.sort();
        const pairKey = pair.join(":");
        this.decreaseCounter(pairKey);
    }

    /**
     * @params peerPublicKey
     * @returns true if any limit is reached.
     */
    protected checkClientsOverflow(peerPublicKey: string): boolean {
        if (this.handshakeFactoryConfig.maxConnectionsPerClient !== undefined) {
            const clientCount = this.readCounter(peerPublicKey);
            if (clientCount >= this.handshakeFactoryConfig.maxConnectionsPerClient) {
                return true;
            }
        }

        if (this.handshakeFactoryConfig.maxConnectionsPerClientPair !== undefined) {
            const pair = [peerPublicKey, this.handshakeFactoryConfig.keyPair.publicKey.toString("hex")];
            pair.sort();
            const pairKey = pair.join(":");
            const clientPairCount = this.readCounter(pairKey);
            if (clientPairCount >= this.handshakeFactoryConfig.maxConnectionsPerClientPair) {
                return true;
            }
        }

        return false;
    }

    onHandshakeError(callback: HandshakeErrorCallback) {
        this.hookEvent(EVENTS.HANDSHAKE_ERROR.name, callback);
    }

    onHandshake(callback: HandshakeCallback) {
        this.hookEvent(EVENTS.HANDSHAKE.name, callback);
    }
}
