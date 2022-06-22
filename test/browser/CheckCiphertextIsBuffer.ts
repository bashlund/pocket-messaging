//
// Manual testing (node):
// 1. Build with tsc
// 2. Run the resulting .js with node:
//    node ./CheckCiphertextIsBuffer.js
//
// Manual testing (browser):
// 1. Build with browserify
//    npx browserify ./CheckCiphertextIsBuffer.js > ./output.js
// 3. Run from browser:
//    [...] <script src="./output.js"></script> [...]
//
import {box, unbox, randomBytes, init} from "./Crypto";

async function encryption() {
    // TODO test box and unbox

    await init();  // libsodium

    const chunk = Buffer.from("Hello World!");
    const outgoingNonce = Buffer.alloc(24).fill(1);
    const outgoingKey = Buffer.alloc(32).fill(2);
    const [ciphertext, nextNonce] = box(chunk, outgoingNonce, outgoingKey);
    console.warn("Ciphertext equals chunk ?", ciphertext.equals(chunk));
    console.warn("Ciphertext is typeof object ?", typeof(ciphertext) == "object");
    console.warn("Ciphertext isBuffer ?", Buffer.isBuffer(ciphertext) == true);

    const incomingNonce = Buffer.alloc(24).fill(1);
    const incomingKey = outgoingKey;
    const [decrypted, nextNonce2] = unbox(ciphertext, incomingNonce, incomingKey) || [];
    console.warn(Boolean(decrypted?.equals(chunk)));
    console.warn(nextNonce2 && Boolean(nextNonce?.equals(nextNonce2)) || false);
}

encryption();
