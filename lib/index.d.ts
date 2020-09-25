/// <reference types="node" />
import { SIDH, keys, Sha3 } from 'node-sidh';
export interface keyPair extends keys {
}
export declare class SikeSig {
    sidh: SIDH;
    sha3: Sha3;
    constructor();
    createKeyPairB(): Promise<keyPair>;
    createSignature(msg: Buffer, keyPair: keyPair): Promise<Buffer>;
    verifySignature(msg: Buffer, sig: Buffer): Promise<boolean>;
}
//# sourceMappingURL=index.d.ts.map