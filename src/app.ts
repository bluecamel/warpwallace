import { HMAC_SHA256, pbkdf2, scrypt, util, WordArray } from 'triplesec';
import { generate } from 'keybase-bitcoin';

function from_utf8(s, i) {
  const b = new Buffer(s, 'utf8');
  const b2 = Buffer.concat([b, (new Buffer([i]))]);
  const ret = WordArray.from_buffer(b2);
  util.scrub_buffer(b);
  util.scrub_buffer(b2);
  return ret;
}

const passphrase = 'PuACRv0R';
const salt = '';

let seeds = [];

function progressHook(progress) {
  console.log({progress});
}

const params = {
  N: 18,
  p: 1,
  r: 8,
  dkLen: 32,
  pbkdf2c: 65536,
  progress_hook: progressHook,
  key: from_utf8(passphrase, 1),
  salt: from_utf8(salt, 1)
};

const params2 = {
  key: from_utf8(passphrase, 2),
  salt: from_utf8(salt, 2),
  c: params.pbkdf2c,
  dkLen: params.dkLen,
  progress_hook: progressHook,
  klass: HMAC_SHA256
};

scrypt(params, (seed1) => {
  seeds.push(seed1.to_buffer());

  pbkdf2(params2, (seed2) => {
    seeds.push(seed2.to_buffer());
    console.log({seeds});

    const xor = seed1.xor(seed2, {});
    console.log({xor});

    const seedFinal = seed1.to_buffer();
    seeds.push(seedFinal);

    for (const obj of [seed1, seed2, params.key, params2.key]) {
      obj.scrub();
    }

    const out = generate(seedFinal);
    console.log({out, seeds});
  });
});
