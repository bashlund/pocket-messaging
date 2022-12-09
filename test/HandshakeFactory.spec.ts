import { TestSuite, Test, AfterAll, BeforeAll, expect } from 'testyts';

import {HandshakeFactory} from "../src/HandshakeFactory";
import {TCPClient} from "pocket-sockets";
const assert = require("assert");

@TestSuite()
export class HandshakeFactoryConstructor {
    @Test()
    public successful_call() {
        assert.doesNotThrow(() => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    maxConnections: 9
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0)
            });

            //@ts-ignore
            assert(Object.keys(handshakeFactory.getHandshakeFactoryConfig().socketFactoryConfig).length == 1);
            //@ts-ignore
            assert(handshakeFactory.getHandshakeFactoryConfig().socketFactoryConfig.maxConnections == 9);
            //@ts-ignore
            assert(Object.keys(handshakeFactory.stats.counters).length == 0);
            //@ts-ignore
            assert(Object.keys(handshakeFactory.handlers).length == 0);
            //@ts-ignore
            assert(handshakeFactory.serverClientSockets.length == 0);
            //@ts-ignore
            assert(handshakeFactory._isClosed == false);
            //@ts-ignore
            assert(handshakeFactory._isShutdown == false);
        });
    }
}

@TestSuite()
export class HandshakeFactoryHandleOnConnect {
    @Test()
    public successful_call_client() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            const clientSocket = new TCPClient(handshakeFactory.getHandshakeFactoryConfig().socketFactoryConfig.client.clientOptions);

            //@ts-ignore
            const callback = await handshakeFactory.handleOnConnect({
                client: clientSocket,
                isServer: false
            });
        });
    }

    @Test()
    public successful_call_server() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            const clientSocket = new TCPClient(handshakeFactory.getHandshakeFactoryConfig().socketFactoryConfig.client.clientOptions);

            //@ts-ignore
            const callback = await handshakeFactory.handleOnConnect({
                client: clientSocket,
                isServer: true
            });
        });
    }

    @Test()
    public successful_call_client_missing_serverPublicKey() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0)
            });

            //@ts-ignore
            const clientSocket = new TCPClient(handshakeFactory.getHandshakeFactoryConfig().socketFactoryConfig.client.clientOptions);

            let clientSocketCloseCalled = false;
            //@ts-ignore
            clientSocket.close = function() {
                clientSocketCloseCalled = true;
            };

            //@ts-ignore
            const callback = await handshakeFactory.handleOnConnect({
                client: clientSocket,
                isServer: false
            });

            //@ts-ignore
            assert(clientSocketCloseCalled == true);
        });
    }

    @Test()
    public successful_call_client_handshake_error() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            const clientSocket = new TCPClient(handshakeFactory.getHandshakeFactoryConfig().socketFactoryConfig.client.clientOptions);

            //@ts-ignore
            handshakeFactory.triggerEvent = function(name, args) {
                assert(name == "HANDSHAKE_ERROR" || name == "ERROR");
                if(args.e && args.e.error) {
                    assert(args.e.error == "Error: Timeout");
                } else {
                    assert(args.error == "Error: Timeout");
                }
            };

            //@ts-ignore
            const callback = await handshakeFactory.handleOnConnect({
                client: clientSocket,
                isServer: false
            });
        });
    }
}

@TestSuite()
export class HandshakeFactoryInit {
    @Test()
    public successful_call() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            const handleOnConnectFn = function(){
            };
            //@ts-ignore
            handshakeFactory.handleOnConnect = handleOnConnectFn;

            handshakeFactory.onConnect = function(fn){
                onConnectCalled = true;
                assert(fn == handleOnConnectFn);
            };

            let onConnectCalled = false;
            handshakeFactory.onConnect = function(){
                onConnectCalled = true;
            };
            //@ts-ignore
            handshakeFactory.init();

            //@ts-ignore
            assert(onConnectCalled == true);
        });
    }
}

@TestSuite()
export class HandshakeFactoryIncreaseDecreaseClientsCounter {
    @Test()
    public successful_call() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            let counter = handshakeFactory.readCounter("ABBA");
            assert(counter == 0);

            //@ts-ignore
            handshakeFactory.increaseCounter("ABBA");

            //@ts-ignore
            counter = handshakeFactory.readCounter("ABBA");
            assert(counter == 1);

            //@ts-ignore
            handshakeFactory.increaseCounter("ABBA");
            //@ts-ignore
            counter = handshakeFactory.readCounter("ABBA");
            assert(counter == 2);

            //@ts-ignore
            handshakeFactory.decreaseCounter("ABBA");
            //@ts-ignore
            counter = handshakeFactory.readCounter("ABBA");
            assert(counter == 1);
        });
    }
}

@TestSuite()
export class HandshakeFactoryCheckClientsOverflow {
    @Test()
    public configuration_undefined() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            let overflows = handshakeFactory.checkClientsOverflow("ABBA");
            assert(overflows == false);
        });
    }

    @Test()
    public overflows() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 1
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
                maxConnectionsPerClient: 1
            });

            //@ts-ignore
            handshakeFactory.increaseCounter("ABBA");

            //@ts-ignore
            let overflows = handshakeFactory.checkClientsOverflow("ABBA");
            assert(overflows == true);
        });
    }

    @Test()
    public within_range() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 1
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
                maxConnectionsPerClient: 2
            });

            //@ts-ignore
            handshakeFactory.increaseCounter("ABBA");

            //@ts-ignore
            let overflows = handshakeFactory.checkClientsOverflow("ABBA");
            assert(overflows == false);
        });
    }
}

@TestSuite()
export class HandshakeFactoryOnHandshakeError {
    @Test()
    public successful_call() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            handshakeFactory.hookEvent = function(name, callback) {
                assert(name == "HANDSHAKE_ERROR");
                assert(callback == cb);
            };

            const cb = function() {
            }
            handshakeFactory.onHandshakeError(cb);
        });
    }
}

@TestSuite()
export class HandshakeFactoryOnHandshake {
    @Test()
    public successful_call() {
        assert.doesNotThrow(async () => {
            let handshakeFactory = new HandshakeFactory({
                pingInterval: 0,
                socketFactoryConfig: {
                    client: {
                        socketType: "TCP",
                        clientOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        reconnectDelay: 0,
                    },

                    server: {
                        socketType: "WebSocket",
                        serverOptions: {
                            "host": "host.com",
                            "port": 99
                        },
                        deniedIPs: ["192.168.5.5"],
                        allowedIPs: ["127.0.0.1", "localhost"],
                    },
                    maxConnections: 0
                },
                keyPair: {
                    publicKey: Buffer.alloc(0),
                    secretKey: Buffer.alloc(0)
                },
                discriminator: Buffer.alloc(0),
                serverPublicKey: Buffer.alloc(0),
            });

            //@ts-ignore
            handshakeFactory.hookEvent = function(name, callback) {
                assert(name == "HANDSHAKE");
                assert(callback == cb);
            };

            const cb = function() {
            }
            handshakeFactory.onHandshake(cb);
        });
    }
}
