/// <reference types="node" />
import { SIDH, keys } from 'node-sidh/lib';
export interface keyPair extends keys {
}
export declare class SikeSig {
    sidh: SIDH;
    constructor();
    createKeyPairB(): Promise<keyPair>;
    createSignature(msg: Buffer, keyPair: keyPair): Promise<Buffer>;
    verifySignature(msg: Buffer, signerPubKey: Buffer, sig: Buffer): Promise<any>;
}
//# sourceMappingURL=index.d.ts.map