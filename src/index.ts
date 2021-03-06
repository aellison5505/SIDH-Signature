import { SIDH, keys, Sha3 } from 'node-sidh';

import { randomFillSync } from 'crypto';

export interface keyPair extends keys{};

export class SikeSig {

    sidh: SIDH;
    sha3: Sha3;

    constructor() {
        this.sidh = new SIDH();
        this.sha3 = new Sha3();
    }

    async createKeyPairB(): Promise<keyPair> {
        return await this.sidh.senderKeys();        
    }   

     async createSignature(msg: Buffer, keyPair: keyPair): Promise<Buffer> {
        return new Promise<Buffer>(async (res)=>{
        const shake256 = this.sha3.shake256;

        let randomBytes =  Buffer.alloc(32);
        randomFillSync(randomBytes);

        let preShaKeyHash = Buffer.concat([randomBytes,keyPair.PrivateKey]);
        //let shaKeyHash = createHash('sha512').update(preShaKeyHash).digest();
        let shaKeyHash = await shake256(preShaKeyHash, 64);
        //let publicKeyHash = createHash('sha256').update(keyPair.PublicKey).digest();
        let publicKeyHash = await shake256(keyPair.PublicKey, 32);
        let msgBytes = Buffer.concat([publicKeyHash,shaKeyHash,msg]);

        // let preKey = createHash('sha512').update(Buffer.concat([keyPair.PublicKey,shaKeyHash, msg])).digest();
        let private_key_A = Buffer.alloc(47);
        private_key_A = await shake256(Buffer.concat([keyPair.PublicKey,shaKeyHash, msg]), 47);

        //let private_key_A = Buffer.alloc(47);
       // preKey.copy(private_key_A,0,0,47);
        private_key_A[46] &= 0x0F;   
        
        let pk = await this.sidh.createPubA(private_key_A);
        let j = await this.sidh.sharedKeySender(keyPair.PrivateKey, pk);
        //let h = createHash('sha512').update(j).digest();
        let h = await shake256(j, 128);
        let hmsg = Buffer.alloc(128);
        for (let i = 0; i < hmsg.length; i++) {
            hmsg[i] = msgBytes[i] ^ h[i];
        }
        
        let sig = Buffer.concat([keyPair.PublicKey,shaKeyHash,hmsg])
        res(sig);

        });
    }

    async verifySignature(msg: Buffer, sig: Buffer): Promise<boolean> {
        return new Promise<boolean>(async (res,err)=>{
            const shake256 = this.sha3.shake256;
            let signerPubKey = Buffer.alloc(564);
            let shaKeyHash = Buffer.alloc(64);
            let hmsg = Buffer.alloc(128);

            sig.copy(signerPubKey,0,0,564);
            sig.copy(shaKeyHash,0,564,564+64);
          //  sig.copy(ck_msg,0,564+64,564+64+32);
            sig.copy(hmsg,0,564+64,564+64+128);

            // let signerPubKeyHash = createHash('sha256').update(signerPubKey).digest();
            let signerPubKeyHash = await shake256(signerPubKey, 32);
            let msgBytes = Buffer.concat([signerPubKeyHash,shaKeyHash, msg]);
            
            //let preKey = createHash('sha512').update(Buffer.concat([signerPubKey, shaKeyHash, msg])).digest();

            let private_key_A = Buffer.alloc(47);
            private_key_A = await shake256(Buffer.concat([signerPubKey,shaKeyHash, msg]), 47);
            //preKey.copy(private_key_A,0,0,47);
            private_key_A[46] &= 0x0F; 

            let j = await this.sidh.sharedKey(private_key_A, signerPubKey);
            //let h = createHash('sha512').update(j).digest();
            let h = await shake256(j, 128);
            let chk = Buffer.alloc(128);
            for (let i = 0; i < chk.length; i++) {
                chk[i] = hmsg[i] ^ h[i];
            };

            let ck_pubKeyHash = Buffer.alloc(32);
            let ck_shaKeyHash = Buffer.alloc(64);
            let ck_msg = Buffer.alloc(32);
            chk.copy(ck_pubKeyHash,0,0,32);
            chk.copy(ck_shaKeyHash,0,32,32+64);
            chk.copy(ck_msg,0,32+64,32+64+32);

            (chk.compare(msgBytes) === 0 ? res(true) : err(new Error('does not match')));

            (Buffer.compare(ck_msg,msg) === 0 ?  null: err(new Error('bad msg')));

            (Buffer.compare(signerPubKeyHash,ck_pubKeyHash) === 0 ?  null: err(new Error('signer public key not matched')));

            (Buffer.compare(shaKeyHash,ck_shaKeyHash) === 0 ?  null: err(new Error('signer secret key hash not matched')));

            err(new Error('not verified'));
            
          //  res(Buffer.compare(hmsg,chk));
        });

    }

}