import {box, unbox, init} from "./Crypto";

import {
    ClientInterface,
    SocketErrorCallback,
    SocketDataCallback,
    SocketConnectCallback,
    SocketCloseCallback,
} from "pocket-sockets";

/**
 * Wrap an already connected and handshooked socket client as encrypted.
 *
 */
export class EncryptedClient implements ClientInterface {
    protected handlers: {[name: string]: ((args?: any) => void)[]} = {};
    protected incomingData: Buffer;

    constructor(protected client: ClientInterface,
            protected outgoingKey: Buffer,
            protected outgoingNonce: Buffer,
            protected incomingKey: Buffer,
            protected incomingNonce: Buffer,
            protected peerPublicKey: Buffer) {

        this.incomingData = Buffer.alloc(0);
    }

    public async init() {
        await init();  // Init sodium
    }

    public getSocket(): any {
        return this.client.getSocket();
    }

    public isWebSocket(): boolean {
        return this.client.isWebSocket();
    }

    public isTextMode(): boolean {
        return this.client.isTextMode();
    }

    public connect() {
        throw new Error("The EncryptedSocket's underlaying socket should already have been connected");
    }

    public unRead(data: Buffer) {  //eslint-disable-line @typescript-eslint/no-unused-vars
        throw new Error("unRead function not available in EncryptedSocket");
    }

    public getPeerPublicKey(): Buffer {
        return this.peerPublicKey;
    }

    public close() {
        this.client.close();
    }

    public isClosed(): boolean {
        return this.client.isClosed();
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

    public onError(fn: SocketErrorCallback) {
        this.client.onError(fn);
    }

    public offError(fn: SocketErrorCallback) {
        this.client.offError(fn);
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

    public onConnect(fn: SocketConnectCallback) {
        this.client.onConnect(fn);
    }

    public offConnect(fn: SocketConnectCallback) {
        this.client.offConnect(fn);
    }

    public onClose(fn: SocketCloseCallback) {
        this.client.onClose(fn);
    }

    public offClose(fn: SocketCloseCallback) {
        this.client.offClose(fn);
    }

    public getLocalAddress(): string | undefined {
        return this.client.getLocalAddress();
    }

    public getRemoteAddress(): string | undefined {
        return this.client.getRemoteAddress();
    }

    public getRemotePort(): number | undefined {
        return this.client.getRemotePort();
    }

    public getLocalPort(): number | undefined {
        return this.client.getLocalPort();
    }

    public getClient(): ClientInterface {
        return this.client;
    }

    protected hookEvent(type: string, callback: (args?: any) => void) {
        const cbs = this.handlers[type] || [];
        this.handlers[type] = cbs;
        cbs.push(callback);
    }

    protected unhookEvent(type: string, callback: (args?: any) => void) {
        const cbs = (this.handlers[type] || []).filter( (cb: (args?: any) => void) => callback !== cb );
        this.handlers[type] = cbs;
    }

    protected triggerEvent(type: string, ...args: any) {
        const cbs = this.handlers[type] || [];
        cbs.forEach( (callback) => {
            callback(...args);
        });
    }
}
