import { TestSuite, Test, AfterAll, expect } from 'testyts';
import nacl from "tweetnacl";
import {box, unbox, randomBytes} from "../src/Crypto";

@TestSuite()
export class CryptoSpec {
    @Test()
    public encryption() {
        // TODO test box and unbox
    }

    @Test()
    public bytes() {
        let data = randomBytes(0);
        expect.toBeTrue(data.length == 0);

        data = randomBytes(11);
        expect.toBeTrue(data.length == 11);

        data = randomBytes(200);
        expect.toBeTrue(data.length == 200);
    }
}
