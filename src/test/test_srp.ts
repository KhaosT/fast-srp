// @ts-ignore
import * as vows from 'vows';
import * as assert from 'assert';
import * as srp from '..';

delete exports.__esModule;

const params = srp.params[4096];

const salt = Buffer.from('salty');
const identity = Buffer.from('alice');
const password = Buffer.from('password123');

assert(params, 'missing parameters');

let client: srp.Client, server: srp.Server;
let a: Buffer, A: Buffer;
let b: Buffer, B: Buffer;
let verifier: Buffer;
// let S_client, S_server;

vows.describe('srp.js').addBatch({
  'create Verifier'() {
    verifier = srp.computeVerifier(params, salt, identity, password);
    assert.equal(verifier.toString('hex'), 'f0e47f50f5dead8db8d93a279e3b62d6ff50854b31fbd3474a886bef916261717e84dd4fb8b4d27feaa5146db7b1cbbc274fdf96a132b5029c2cd72527427a9b9809d5a4d018252928b4fc343bc17ce63c1859d5806f5466014fc361002d8890aeb4d6316ff37331fc2761be0144c91cdd8e00ed0138c0ce51534d1b9a9ba629d7be34d2742dd4097daabc9ecb7aaad89e53c342b038f1d2adae1f2410b7884a3e9a124c357e421bccd4524467e1922660e0a4460c5f7c38c0877b65f6e32f28296282a93fc11bbabb7bb69bf1b3f9391991d8a86dd05e15000b7e38ba38a536bb0bf59c808ec25e791b8944719488b8087df8bfd7ff20822997a53f6c86f3d45d004476d6303301376bb25a9f94b552cce5ed40de5dd7da8027d754fa5f66738c7e3fc4ef3e20d625df62cbe6e7adfc21e47880d8a6ada37e60370fd4d8fc82672a90c29f2e72f35652649d68348de6f36d0e435c8bd42dd00155d35d501becc0661b43e04cdb2da84ce92b8bf49935d73d75efcbd1176d7bbccc3cc4d4b5fefcc02d478614ee1681d2ff3c711a61a7686eb852ae06fb8227be21fb8802719b1271ba1c02b13bbf0a2c2e459d9bedcc8d1269f6a785cb4563aa791b38fb038269f63f58f47e9051499549789269cc7b8ec7026fc34ba73289c4af829d5a532e723967ce9b6c023ef0fd0cfe37f51f10f19463b6534159a09ddd2f51f3b30033');
  },

  'create a and b': {
    topic(this: any) {(async () => {
      a = await srp.genKey(64);
      b = await srp.genKey(32);
      this.callback();
    })()},

    'use a and b'() {
      client = new srp.Client(params, salt, identity, password, a);

      // client produces A
      A = client.computeA();

      // create server
      server = new srp.Server(params, verifier, b);

      // server produces B
      B = server.computeB();

      // server accepts A
      server.setA(A);

      // client doesn't produce M1 too early
      assert.throws(() => client.computeM1(), /incomplete protocol/);

      // client accepts B
      client.setB(B);

      // client produces M1 now
      client.computeM1();

      // server likes client's M1
      server.checkM1(client.computeM1());
      const serverM2 = server.computeM2();

      // client and server agree on K
      const client_K = client.computeK();
      const server_K = server.computeK();
      assert.equal(client_K.toString('hex'), server_K.toString('hex'));

      // server is authentic
      assert.doesNotThrow(() => client.checkM2(serverM2), 'M2 didn\'t check');
    },

    'server rejects wrong M1'() {
      const bad_client = new srp.Client(params, salt, identity, Buffer.from('bad'), a);
      const server2 = new srp.Server(params, verifier, b);
      bad_client.setB(server2.computeB());
      assert.throws(() => server.checkM1(bad_client.computeM1()), /client did not use the same password/);
    },

    'server rejects bad A'() {
      // client's "A" must be 1..N-1 . Reject 0 and N and N+1. We should
      // reject 2*N too, but our Buffer-length checks reject it before the
      // number itself is examined.

      var server2 = new srp.Server(params, verifier, b);
      var Azero = Buffer.alloc(params.N_length_bits / 8);
      Azero.fill(0);
//!      var AN = params.N.toBuffer();
//!      var AN1 = params.N.add(1).toBuffer();
      var AN = Buffer.from(params.N.toString(16), 'hex');
      var AN1 = Buffer.from(params.N.add(1).toString(16), 'hex');
      assert.throws(() => server2.setA(Azero), /invalid client-supplied "A"/);
      assert.throws(() => server2.setA(AN), /invalid client-supplied "A"/);
      assert.throws(() => server2.setA(AN1), /invalid client-supplied "A"/);
    },

    'client rejects bad B'() {
      // server's "B" must be 1..N-1 . Reject 0 and N and N+1
      var client2 = new srp.Client(params, salt, identity, password, a);
      var Bzero = Buffer.alloc(params.N_length_bits / 8);
      Bzero.fill(0, 0, params.N_length_bits / 8);
//!      var BN = params.N.toBuffer();
//!      var BN1 = params.N.add(1).toBuffer();
      var BN = Buffer.from(params.N.toString(16), 'hex');
      var BN1 = Buffer.from(params.N.add(1).toString(16), 'hex');
      assert.throws(() => client2.setB(Bzero), /invalid server-supplied "B"/);
      assert.throws(() => client2.setB(BN), /invalid server-supplied "B"/);
      assert.throws(() => client2.setB(BN1), /invalid server-supplied "B"/);
    },

    'client rejects bad M2'() {
      client = new srp.Client(params, salt, identity, password, a);

      // client produces A
      A = client.computeA();

      // create server
      server = new srp.Server(params, verifier, b);

      // server produces B
      B = server.computeB();

      // server accepts A
      server.setA(A);

      // client accepts B
      client.setB(B);

      // client produces M1 now
      client.computeM1();

      // server likes client's M1
      server.checkM1(client.computeM1());
      let serverM2 = server.computeM2();
      // we tamper with the server's M2
      serverM2 = Buffer.from('a');

      // client and server agree on K
      var client_K = client.computeK();
      var server_K = server.computeK();
      assert.equal(client_K.toString('hex'), server_K.toString('hex'));

      // server is NOT authentic
      assert.throws(() => client.checkM2(serverM2), 'M2 didn\'t check');
    },
  },
}).export(module);
