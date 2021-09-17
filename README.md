# pocket-messaging

A small, eventdriven messaging library written in TypeScript for client/server communication over TCP or WebSockets with support for TLS encryption.

Runs in browser and NodeJS.

## Example
For a quick glimpse of what it looks like to set up two participants exchanging call and response messages and then finalizing the connections, follow the example below:
```javascript
let [socket1, socket2] = CreatePair();
let messaging1 = new Messaging(socket1);
let messaging2 = new Messaging(socket2);

messaging1.open();
messaging2.open();

// Send message A from participant #1 to participant #2, then close upon reply
(async function() {
    const data = Buffer.from("A");
    const eventEmitter = messaging1.send("ping", data, 10000, true);
    if(eventEmitter) {
        const reply = await once(eventEmitter, "reply");
    }
    messaging1.close();
}) ();

// Send message B from participant #2 to participant #1, then close upon reply
(async function() {
    const eventEmitter = messaging2.getEventEmitter();
    const event = await once(eventEmitter, "route");
    const data = Buffer.from("B");
    const eventEmitterSend = messaging2.send(event.fromMsgId, data, 10000);
    if(eventEmitterSend) {
        const reply = await once(eventEmitterSend, "mixed");
    }
    messaging2.close();
}) ();
```

For a complete example, please refer to the [./example](https://github.com/bashlund/pocket-messaging/tree/main/example) directory.

## Reference
Code documentation and API references are available in the official [Wiki](https://github.com/bashlund/pocket-messaging/wiki): [https://github.com/bashlund/pocket-messaging/wiki](https://github.com/bashlund/pocket-messaging/wiki).


## License
This project is released under the _MIT_ license.
