import {box, unbox, init} from "./Crypto";

import {
    ClientInterface,
    SocketDataCallback,
    WrappedClient,
} from "pocket-sockets";

/**
 * Wrap an already connected and handshooked socket client as encrypted.
 *
 */
export class EncryptedClient extends WrappedClient {
    protected handlers: {[type: string]: ((data?: any) => void)[]} = {};

    protected incomingData: Buffer;

    constructor(client: ClientInterface,
            protected outgoingKey: Buffer,
            protected outgoingNonce: Buffer,
            protected incomingKey: Buffer,
            protected incomingNonce: Buffer,
            protected peerPublicKey: Buffer) {

        super(client);

        this.incomingData = Buffer.alloc(0);
    }

    public async init() {
        await super.init();

        await init();  // Init sodium
    }

    public unRead(data: Buffer) {  //eslint-disable-line @typescript-eslint/no-unused-vars
        throw new Error("unRead function not available in EncryptedClient");
    }

    public getPeerPublicKey(): Buffer {
        return this.peerPublicKey;
    }

    protected decryptData() {
        const ret = unbox(this.incomingData, this.incomingNonce, this.incomingKey);

        if (!ret) {
            // Not enough data in chunk
            return;
        }

        const [decrypted, nextNonce, bytesConsumed] = ret;

        this.incomingNonce = nextNonce;

        this.incomingData = this.incomingData.slice(bytesConsumed);

        this.triggerEvent("data", decrypted);

        if (this.incomingData.length > 0) {
            this.decryptData();
        }
    }

    public send(data: Buffer) {
        if (Buffer.isBuffer(data)) {
            // encrypt data
            const [encryptedData, nextNonce] = box(data, this.outgoingNonce, this.outgoingKey);

            this.outgoingNonce = nextNonce;

            this.client.send(encryptedData);
        }
        else {
            throw new Error("EncryptedClient does not work with text data");
        }
    }

    public onData(fn: SocketDataCallback) {
        this.hookEvent("data", fn);

        if ((this.handlers["data"] ?? []).length === 1) {
            this.client.onData( this.handleOnData );
        }
    }

    public offData(fn: SocketDataCallback) {
        this.unhookEvent("data", fn);

        if ((this.handlers["data"] ?? []).length === 0) {
            this.client.offData( this.handleOnData );
        }
    }

    protected handleOnData = async (data: Buffer | string) => {
        if (Buffer.isBuffer(data)) {
            this.incomingData = Buffer.concat([this.incomingData, data]);
            this.decryptData();
        }
        else {
            throw new Error("EncryptedClient does not work with text data");
        }
    };

    protected hookEvent(type: string, callback: (...args: any[]) => void) {
        const cbs = this.handlers[type] || [];
        this.handlers[type] = cbs;
        cbs.push(callback);
    }

    protected unhookEvent(type: string, callback: (...args: any[]) => void) {
        const cbs = (this.handlers[type] || []).filter( (cb: (data?: any[]) => void) =>
            callback !== cb );

        this.handlers[type] = cbs;
    }

    protected triggerEvent(type: string, ...args: any[]) {
        const cbs = this.handlers[type] || [];
        cbs.forEach( callback => {
            callback(...args);
        });
    }
}
