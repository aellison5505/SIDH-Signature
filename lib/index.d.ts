/// <reference types="node" />
import { SIDH, keys } from 'node-sidh';
export interface keyPair extends keys {
}
export declare class SikeSig {
    sidh: SIDH;
    constructor();
    createKeyPairB(): Promise<keyPair>;
    createSignature(msg: Buffer, keyPair: keyPair): Promise<Buffer>;
    verifySignature(msg: Buffer, sig: Buffer): Promise<boolean>;
}
//# sourceMappingURL=index.d.ts.map