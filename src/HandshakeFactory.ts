import {
    SocketFactory,
    SocketFactoryConnectCallback,
    ClientInterface,
} from "pocket-sockets";

import {
    HandshakeFactoryConfig,
    HandshakeResult,
    HandshakeFactoryInterface,
    HandshakeFactoryHandshakeCallback,
    HandshakeFactoryHandshakeErrorCallback,
    HandshakeFactoryPublicKeyOverflowCallback,
    EVENT_HANDSHAKEFACTORY_HANDSHAKE_ERROR,
    EVENT_HANDSHAKEFACTORY_HANDSHAKE,
    EVENT_HANDSHAKEFACTORY_PUBLICKEY_OVERFLOW,
} from "./types";

import {
    HandshakeAsServer,
    HandshakeAsClient,
} from "./Handshake";

import {
    EncryptedClient,
} from "./EncryptedClient";

/**
 * This class extends the SocketFactory with handshake capabilties.
 * The SocketFactory EVENTS objects is redeclared here and extended.
 */
export class HandshakeFactory extends SocketFactory implements HandshakeFactoryInterface {
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

    protected handleOnConnect: SocketFactoryConnectCallback = async (client: ClientInterface, isServer: boolean) => {
        try {
            let handshakeResult: HandshakeResult;

            let peerData: Buffer | undefined;

            if (typeof this.handshakeFactoryConfig.peerData === "function") {
                peerData = this.handshakeFactoryConfig.peerData(isServer);
            }
            else {
                peerData = this.handshakeFactoryConfig.peerData;
            }

            let encryptedClient: EncryptedClient | undefined;

            if (isServer) {
                handshakeResult = await HandshakeAsServer(client,
                    this.handshakeFactoryConfig.keyPair.secretKey,
                    this.handshakeFactoryConfig.keyPair.publicKey,
                    this.handshakeFactoryConfig.discriminator,
                    this.handshakeFactoryConfig.allowedClients, peerData);

                encryptedClient = new EncryptedClient(client,
                    handshakeResult.serverToClientKey,
                    handshakeResult.serverNonce,
                    handshakeResult.clientToServerKey,
                    handshakeResult.clientNonce,
                    handshakeResult.peerLongtermPk);
            }
            else {
                if (!this.handshakeFactoryConfig.serverPublicKey) {
                    client.close();
                    return;
                }

                handshakeResult = await HandshakeAsClient(client,
                    this.handshakeFactoryConfig.keyPair.secretKey,
                    this.handshakeFactoryConfig.keyPair.publicKey,
                    this.handshakeFactoryConfig.serverPublicKey,
                    this.handshakeFactoryConfig.discriminator, peerData);

                encryptedClient = new EncryptedClient(client,
                    handshakeResult.clientToServerKey,
                    handshakeResult.clientNonce,
                    handshakeResult.serverToClientKey,
                    handshakeResult.serverNonce,
                    handshakeResult.peerLongtermPk);
            }

            if (!handshakeResult || !encryptedClient) {
                return;
            }

            const publicKeyStr = handshakeResult.peerLongtermPk.toString("hex");

            if (this.checkClientsOverflow(publicKeyStr)) {

                const publicKeyOverflowEvent: Parameters<HandshakeFactoryPublicKeyOverflowCallback> =
                    [handshakeResult.peerLongtermPk];

                this.triggerEvent(EVENT_HANDSHAKEFACTORY_PUBLICKEY_OVERFLOW,
                    ...publicKeyOverflowEvent);

                client.close();

                return;
            }

            this.increaseClientsCounter(publicKeyStr);

            client.onClose( () => {
                this.decreaseClientsCounter(publicKeyStr);
            });

            const handshakeEvent: Parameters<HandshakeFactoryHandshakeCallback> =
                [isServer, client, encryptedClient, handshakeResult];

            this.triggerEvent(EVENT_HANDSHAKEFACTORY_HANDSHAKE,
                ...handshakeEvent);
        }
        catch(error) {
            const handshakeErrorEvent: Parameters<HandshakeFactoryHandshakeErrorCallback> =
                [error as Error];

            this.triggerEvent(EVENT_HANDSHAKEFACTORY_HANDSHAKE_ERROR,
                ...handshakeErrorEvent);

            client.close();
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

    /**
     * Detect specific error in the handshake process.
     * This error is also emitted on the general onError event hook provided by SocketFactory.
     */
    public onHandshakeError(callback: HandshakeFactoryHandshakeErrorCallback) {
        this.hookEvent(EVENT_HANDSHAKEFACTORY_HANDSHAKE_ERROR, callback);
    }

    public onHandshake(callback: HandshakeFactoryHandshakeCallback) {
        this.hookEvent(EVENT_HANDSHAKEFACTORY_HANDSHAKE, callback);
    }

    public onPublicKeyOverflow(callback: HandshakeFactoryPublicKeyOverflowCallback) {
        this.hookEvent(EVENT_HANDSHAKEFACTORY_PUBLICKEY_OVERFLOW, callback);
    }
}
