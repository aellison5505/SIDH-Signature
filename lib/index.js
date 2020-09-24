"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SikeSig = void 0;
const lib_1 = require("node-sidh/lib");
//import * as nodeSidh from 'node-sidh/lib/node-sidh';
const crypto_1 = require("crypto");
;
class SikeSig {
    constructor() {
        this.sidh = new lib_1.SIDH();
    }
    createKeyPairB() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.sidh.senderKeys();
        });
    }
    createSignature(msg, keyPair) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((res) => __awaiter(this, void 0, void 0, function* () {
                let randomBytes = Buffer.alloc(32);
                crypto_1.randomFillSync(randomBytes);
                let preShaKey = crypto_1.createHash('sha256').update(keyPair.PrivateKey).digest();
                let temp = Buffer.concat([randomBytes, preShaKey]);
                let shaKeyHash = crypto_1.createHash('sha512').update(temp).digest();
                let msgBytes = Buffer.concat([shaKeyHash, msg]);
                let preKey = crypto_1.createHash('sha512').update(msgBytes).digest();
                let private_key_A = Buffer.alloc(47);
                preKey.copy(private_key_A, 0, 0, 47);
                private_key_A[46] &= 0x0F;
                let pk = yield this.sidh.createPubA(private_key_A);
                let j = yield this.sidh.sharedKeySender(keyPair.PrivateKey, pk);
                //let h = createHash('sha512').update(j).digest();
                let hmsg = Buffer.alloc(96);
                for (let i = 0; i < hmsg.length; i++) {
                    hmsg[i] = msgBytes[i] ^ j[i];
                }
                let sig = Buffer.concat([keyPair.PublicKey, msgBytes, hmsg]);
                res(sig);
            }));
        });
    }
    verifySignature(msg, signerPubKey, sig) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((res, err) => __awaiter(this, void 0, void 0, function* () {
                let pubKey = Buffer.alloc(564);
                let shaKeyHash = Buffer.alloc(64);
                let ck_msg = Buffer.alloc(32);
                let hmsg = Buffer.alloc(96);
                sig.copy(pubKey, 0, 0, 564);
                sig.copy(shaKeyHash, 0, 564, 564 + 64);
                sig.copy(ck_msg, 0, 564 + 64, 564 + 64 + 32);
                sig.copy(hmsg, 0, 564 + 64 + 32, 564 + 64 + 32 + 96);
                (Buffer.compare(pubKey, signerPubKey) === 0 ? null : err(new Error('signer public key not matched')));
                (Buffer.compare(ck_msg, msg) === 0 ? null : err(new Error('bad msg')));
                let msgBytes = Buffer.concat([shaKeyHash, msg]);
                let preKey = crypto_1.createHash('sha512').update(msgBytes).digest();
                let private_key_A = Buffer.alloc(47);
                preKey.copy(private_key_A, 0, 0, 47);
                private_key_A[46] &= 0x0F;
                let j = yield this.sidh.sharedKey(private_key_A, pubKey);
                //let h = createHash('sha512').update(j).digest();
                let chk = Buffer.alloc(96);
                for (let i = 0; i < chk.length; i++) {
                    chk[i] = hmsg[i] ^ j[i];
                }
                ;
                (chk.compare(msgBytes) === 0 ? res(true) : err(new Error('does not match')));
                //  res(Buffer.compare(hmsg,chk));
            }));
        });
    }
}
exports.SikeSig = SikeSig;
//# sourceMappingURL=index.js.map