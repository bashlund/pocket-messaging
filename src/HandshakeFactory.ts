import {
    SocketFactory,
    ConnectCallback,
} from "pocket-sockets";

import {
    HandshakeFactoryConfig,
    HandshakeResult,
    HandshakeFactoryInterface,
    EVENTS,
    HandshakeCallback,
    HandshakeErrorCallback,
} from "./types";

import {
    Messaging,
} from "./Messaging";

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

    protected handleOnConnect: ConnectCallback = async (e) => {
        try {
            let handshakeResult: HandshakeResult;

            let peerData: Buffer | undefined;

            if (typeof this.handshakeFactoryConfig.peerData === "function") {
                peerData = this.handshakeFactoryConfig.peerData(e.isServer);
            }
            else {
                peerData = this.handshakeFactoryConfig.peerData;
            }

            let encryptedClient: EncryptedClient | undefined;

            if (e.isServer) {
                handshakeResult = await HandshakeAsServer(e.client, this.handshakeFactoryConfig.keyPair.secretKey, this.handshakeFactoryConfig.keyPair.publicKey, this.handshakeFactoryConfig.discriminator, this.handshakeFactoryConfig.allowedClients, peerData);

                encryptedClient = new EncryptedClient(e.client,
                    handshakeResult.serverToClientKey,
                    handshakeResult.serverNonce,
                    handshakeResult.clientToServerKey,
                    handshakeResult.clientNonce,
                    handshakeResult.peerLongtermPk);

                await encryptedClient.init();
            }
            else {
                if (!this.handshakeFactoryConfig.serverPublicKey) {
                    e.client.close();
                    return;
                }

                handshakeResult = await HandshakeAsClient(e.client, this.handshakeFactoryConfig.keyPair.secretKey, this.handshakeFactoryConfig.keyPair.publicKey, this.handshakeFactoryConfig.serverPublicKey, this.handshakeFactoryConfig.discriminator, peerData);

                encryptedClient = new EncryptedClient(e.client,
                    handshakeResult.clientToServerKey,
                    handshakeResult.clientNonce,
                    handshakeResult.serverToClientKey,
                    handshakeResult.serverNonce,
                    handshakeResult.peerLongtermPk);

                await encryptedClient.init();
            }

            if (!handshakeResult || !encryptedClient) {
                return;
            }

            const messaging = new Messaging(encryptedClient, this.handshakeFactoryConfig.pingInterval);

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

    public onHandshakeError(callback: HandshakeErrorCallback) {
        this.hookEvent(EVENTS.HANDSHAKE_ERROR.name, callback);
    }

    public onHandshake(callback: HandshakeCallback) {
        this.hookEvent(EVENTS.HANDSHAKE.name, callback);
    }
}
