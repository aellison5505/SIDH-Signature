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
const node_sidh_1 = require("node-sidh");
//import * as nodeSidh from 'node-sidh/lib/node-sidh';
const crypto_1 = require("crypto");
;
class SikeSig {
    constructor() {
        this.sidh = new node_sidh_1.SIDH();
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
                let preShaKeyHash = Buffer.concat([randomBytes, keyPair.PrivateKey]);
                let shaKeyHash = crypto_1.createHash('sha512').update(preShaKeyHash).digest();
                let publicKeyHash = crypto_1.createHash('sha256').update(keyPair.PublicKey).digest();
                let msgBytes = Buffer.concat([publicKeyHash, shaKeyHash, msg]);
                let preKey = crypto_1.createHash('sha512').update(Buffer.concat([keyPair.PublicKey, shaKeyHash, msg])).digest();
                let private_key_A = Buffer.alloc(47);
                preKey.copy(private_key_A, 0, 0, 47);
                private_key_A[46] &= 0x0F;
                let pk = yield this.sidh.createPubA(private_key_A);
                let j = yield this.sidh.sharedKeySender(keyPair.PrivateKey, pk);
                //let h = createHash('sha512').update(j).digest();
                let hmsg = Buffer.alloc(128);
                for (let i = 0; i < hmsg.length; i++) {
                    hmsg[i] = msgBytes[i] ^ j[i];
                }
                let sig = Buffer.concat([keyPair.PublicKey, shaKeyHash, hmsg]);
                res(sig);
            }));
        });
    }
    verifySignature(msg, sig) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((res, err) => __awaiter(this, void 0, void 0, function* () {
                let signerPubKey = Buffer.alloc(564);
                let shaKeyHash = Buffer.alloc(64);
                let hmsg = Buffer.alloc(128);
                sig.copy(signerPubKey, 0, 0, 564);
                sig.copy(shaKeyHash, 0, 564, 564 + 64);
                //  sig.copy(ck_msg,0,564+64,564+64+32);
                sig.copy(hmsg, 0, 564 + 64, 564 + 64 + 128);
                let signerPubKeyHash = crypto_1.createHash('sha256').update(signerPubKey).digest();
                let msgBytes = Buffer.concat([signerPubKeyHash, shaKeyHash, msg]);
                let preKey = crypto_1.createHash('sha512').update(Buffer.concat([signerPubKey, shaKeyHash, msg])).digest();
                let private_key_A = Buffer.alloc(47);
                preKey.copy(private_key_A, 0, 0, 47);
                private_key_A[46] &= 0x0F;
                let j = yield this.sidh.sharedKey(private_key_A, signerPubKey);
                //let h = createHash('sha512').update(j).digest();
                let chk = Buffer.alloc(128);
                for (let i = 0; i < chk.length; i++) {
                    chk[i] = hmsg[i] ^ j[i];
                }
                ;
                let ck_pubKeyHash = Buffer.alloc(32);
                let ck_shaKeyHash = Buffer.alloc(64);
                let ck_msg = Buffer.alloc(32);
                chk.copy(ck_pubKeyHash, 0, 0, 32);
                chk.copy(ck_shaKeyHash, 0, 32, 32 + 64);
                chk.copy(ck_msg, 0, 32 + 64, 32 + 64 + 32);
                (chk.compare(msgBytes) === 0 ? res(true) : err(new Error('does not match')));
                (Buffer.compare(ck_msg, msg) === 0 ? null : err(new Error('bad msg')));
                (Buffer.compare(signerPubKeyHash, ck_pubKeyHash) === 0 ? null : err(new Error('signer public key not matched')));
                (Buffer.compare(shaKeyHash, ck_shaKeyHash) === 0 ? null : err(new Error('signer secret key hash not matched')));
                err(new Error('not verified'));
                //  res(Buffer.compare(hmsg,chk));
            }));
        });
    }
}
exports.SikeSig = SikeSig;
//# sourceMappingURL=index.js.map