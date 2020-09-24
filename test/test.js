const { SikeSig } = require('../lib');
const { randomFillSync} = require('crypto')
const expect = require('chai').expect;

describe('SIKE SIG', () =>{
    before(() => {
        this.sidh = new SikeSig();
        this.keys;
        this.sig;
        this.testBuf = Buffer.alloc(32);
        randomFillSync(this.testBuf);
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
            
            this.sig = await this.sidh.createSignature(this.testBuf, this.keys);
        });
        it('should return a signature',()=>{
        //    console.log(this.sig.toString('hex'));
            expect(this.sig.length).to.be.equal(756);
        });
    });

    describe('Verify', () =>{
        before(async () => {
           
            this.good = await this.sidh.verifySignature(this.testBuf,this.keys.PublicKey,this.sig);
             //    console.log(this.sig.toString('hex'));
        });
        it('should return good',()=>{
            expect(this.good).to.be.equal(true);
      });
        it('should catch bad msg',async ()=>{
              let bad = Buffer.from(this.testBuf);
              bad[25] = 0;
              await this.sidh.verifySignature(bad,this.keys.PublicKey,this.sig).catch((err) =>{
                  expect(err.message).to.be.equal('bad msg');
              })
        });
        it('should catch does not match crypt msg',async ()=>{
            let bad = Buffer.from(this.sig);
            bad[564+32+32+32+10] = 0;
            await this.sidh.verifySignature(this.testBuf,this.keys.PublicKey,bad).catch((err) =>{
                expect(err.message).to.be.equal('does not match');
            });
        });

        it('should catch does not match msg_bytes',async ()=>{
            let bad = Buffer.from(this.sig);
            bad[564+10] = 0;
            await this.sidh.verifySignature(this.testBuf,this.keys.PublicKey,bad).catch((err) =>{
                expect(err.message).to.be.equal('does not match');
             });
        });
        it('should catch does not match pub key',async ()=>{
            let bad = Buffer.from(this.keys.PublicKey);
            bad[150] = 0;
            await this.sidh.verifySignature(this.testBuf,bad,this.sig).catch((err) =>{
                expect(err.message).to.be.equal('signer public key not matched');
             });
        });
    });
    });