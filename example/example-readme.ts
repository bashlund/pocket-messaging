//
// example-readme.ts
//
// Run:
//   npx ts-node ./example/example-readme.ts
//
// Expected output:
//   Messaging #1: send ping message (data=A)
//   Messaging #2: received route event (data=A)
//   Messaging #2: reply ping message (data=B)
//   Messaging #1: received message reply (data=B)
//   Messaging #2: received mixed event (type=close)
//

import {Messaging, once} from "../";
import {CreatePair, Client} from "../../pocket-sockets";

let [socket1, socket2] = CreatePair();
let messaging1 = new Messaging(socket1);
let messaging2 = new Messaging(socket2);
messaging1.open();
messaging2.open();

(async function() {
    const data = Buffer.from("A");
    console.log("Messaging #1: send ping message (data=" + data.toString() + ")");
    const eventEmitter = messaging1.send("ping", data, 10000, true);

    if(eventEmitter) {
        const reply = await once(eventEmitter, "reply");
        console.log("Messaging #1: received message reply (data=" + reply.data.toString() + ")");
    }

    messaging1.close();
}) ();

(async function() {
    const eventEmitter = messaging2.getEventEmitter();
    const event = await once(eventEmitter, "route");
    console.log("Messaging #2: received route event (data=" + event.data.toString() + ")");

    const data = Buffer.from("B");
    console.log("Messaging #2: reply ping message (data=" + data.toString() + ")");
    const eventEmitterSend = messaging2.send(event.fromMsgId, data, 10000);

    if(eventEmitterSend) {
        const reply = await once(eventEmitterSend, "mixed");
        console.log("Messaging #2: received mixed event (type=" + reply.type.toString() + ")");
    }

    messaging2.close();
}) ();
