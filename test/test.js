const { SikeSig } = require('../lib');
const { randomFillSync} = require('crypto')
// const chaiPromise = require('chai-as-promised');
const chai = require('chai');
//chai.use(chaiPromise);
const expect = chai.expect;
const { rejects} = require('assert')

describe('SIKE SIG', () =>{
    before(() => {
        this.sidh = new SikeSig();
        this.keys;
        this.sig;
        this.msgBuf = Buffer.alloc(32);
        randomFillSync(this.msgBuf);
    });
   
    describe('get keys', () =>{

    before(async () =>{
        this.keys = await this.sidh.createKeyPairB();
    });
    
    it('Private Key', () => {
        expect(this.keys.PrivateKey.length).to.be.equal(48); 
       });
       it('Public Key', () => {
        expect(this.keys.PublicKey.length).to.be.equal(564); 
       });
    });

    describe('signature', () =>{
        before(async () => {
            //console.log(this.keys.PrivateKey);
            
            this.sig = await this.sidh.createSignature(this.msgBuf, this.keys);
        });
        it('should return a signature',()=>{
        //    console.log(this.sig.toString('hex'));
            expect(this.sig.length).to.be.equal(756);
        });
    });

    describe('Verify', () =>{
        
        it('should return true', async ()=>{
            this.good = await this.sidh.verifySignature(this.msgBuf,this.sig);
            expect(this.good).to.be.equal(true);
        });
        it('should catch bad message hash',async ()=>{
              let bad = Buffer.from(this.msgBuf);
              bad[25] = 0;
              rejects(this.sidh.verifySignature(bad,this.sig));
        });
        it('should catch does not match crypt message',async ()=>{
            let bad = Buffer.from(this.sig);
            bad[564+64+10] = 0;
            rejects(this.sidh.verifySignature(this.msgBuf,bad));
        });
        it('should catch signers public key does not match',async ()=>{
            let bad = Buffer.from(this.sig);
            bad[15] = 0;
            rejects(this.sidh.verifySignature(this.msgBuf,bad));
        });
    });
});