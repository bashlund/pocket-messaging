import {
    SocketFactory,
    Client,
    ConnectCallback,
    ClientRefuseCallback,
} from "pocket-sockets";

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
 * Event emitted when client is successfully handshaked and setup for encryption.
 * Note that the returned Messaging object first needs to be .open()'d to be ready for communication.
 */
export type HandshakeCallback = (e: {messaging: Messaging, isServer: boolean, handshakeResult: HandshakeResult}) => void;

/** Event emitted when client could not handshake. */
export type HandshakeErrorCallback = (e: {client: Client, error: Error}) => void;


/**
 * This class extends the SocketFactory with handshake capabilties.
 *
 * The general SocketFactory EVENT_ERROR is also emitted for EVENT_HANDSHAKE_ERROR and the data property is set to the Client object.
 * The SocketFactory EVENT_CLIENT_REFUSE is extended with a type of HandshakeFactory.EVENT_CLIENT_REFUSE_PUBLICKEY_OVERFLOW.
 */
export class HandshakeFactory extends SocketFactory {
    public static readonly EVENT_HANDSHAKE          = "handshake";
    public static readonly EVENT_HANDSHAKE_ERROR    = "handshakeError";
    public static readonly EVENT_CLIENT_REFUSE_PUBLICKEY_OVERFLOW = "publicKey-overflow";

    protected handshakeFactoryConfig: HandshakeFactoryConfig;

    constructor(handshakeFactoryConfig: HandshakeFactoryConfig) {
        super(handshakeFactoryConfig.socketFactoryConfig);
        this.handshakeFactoryConfig = handshakeFactoryConfig;
    }

    protected handleOnConnect: ConnectCallback = async (e) => {
        try {
            const messaging = new Messaging(e.client);
            let handshakeResult: HandshakeResult;
            if (e.isServer) {
                handshakeResult = await HandshakeAsServer(e.client, this.handshakeFactoryConfig.keyPair.secretKey, this.handshakeFactoryConfig.keyPair.publicKey, this.handshakeFactoryConfig.discriminator, this.handshakeFactoryConfig.allowedClients, this.handshakeFactoryConfig.peerData);
                await messaging.setEncrypted(handshakeResult.serverToClientKey, handshakeResult.serverNonce, handshakeResult.clientToServerKey, handshakeResult.clientNonce, handshakeResult.peerLongtermPk);
            }
            else {
                if (!this.handshakeFactoryConfig.serverPublicKey) {
                    e.client.close();
                    return;
                }
                handshakeResult = await HandshakeAsClient(e.client, this.handshakeFactoryConfig.keyPair.secretKey, this.handshakeFactoryConfig.keyPair.publicKey, this.handshakeFactoryConfig.serverPublicKey, this.handshakeFactoryConfig.discriminator, this.handshakeFactoryConfig.peerData);
                await messaging.setEncrypted(handshakeResult.clientToServerKey, handshakeResult.clientNonce, handshakeResult.serverToClientKey, handshakeResult.serverNonce, handshakeResult.peerLongtermPk);
            }
            if (!handshakeResult) {
                return;
            }

            const publicKeyStr = handshakeResult.peerLongtermPk.toString("hex");
            if (this.checkClientsOverflow(publicKeyStr)) {
                messaging.close();
                this.triggerEvent(HandshakeFactory.EVENT_CLIENT_REFUSE, {type: HandshakeFactory.EVENT_CLIENT_REFUSE_PUBLICKEY_OVERFLOW, key: handshakeResult.peerLongtermPk});
                return;
            }
            this.increaseClientsCounter(publicKeyStr);
            e.client.onClose( () => {
                this.decreaseClientsCounter(publicKeyStr);
            });

            this.triggerEvent(HandshakeFactory.EVENT_HANDSHAKE, {messaging, isServer: e.isServer, handshakeResult});
        }
        catch(error) {
            if (typeof error === "string") {
                error = new Error(error);
            }
            this.triggerEvent(HandshakeFactory.EVENT_HANDSHAKE_ERROR, {client: e.client, error});
            this.triggerEvent(HandshakeFactory.EVENT_ERROR, {type: HandshakeFactory.EVENT_HANDSHAKE_ERROR, error, data: e.client});
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
    protected increaseClientsCounter(publicKey: string) {
        this.increaseCounter(publicKey);
    }

    protected decreaseClientsCounter(publicKey: string) {
        this.decreaseCounter(publicKey);
    }

    /**
     * @params publicKey
     * @returns true if any limit is reached.
     */
    protected checkClientsOverflow(publicKey: string): boolean {
        if (this.handshakeFactoryConfig.maxConnectionsPerClient !== undefined) {
            const clientCount = this.readCounter(publicKey);
            if (clientCount >= this.handshakeFactoryConfig.maxConnectionsPerClient) {
                return true;
            }
        }
        return false;
    }

    onHandshakeError(callback: HandshakeErrorCallback) {
        this.hookEvent(HandshakeFactory.EVENT_HANDSHAKE_ERROR, callback);
    }

    onHandshake(callback: HandshakeCallback) {
        this.hookEvent(HandshakeFactory.EVENT_HANDSHAKE, callback);
    }
}
