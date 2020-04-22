const auth = require('./index.js');
const jwks = require('./jwk.js');
const {
  getPem,
  getUserPoolUri,
  validateJwt,
} = auth;


const knownPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiULGOd7nqw3qfpCkX2r7
OQ3sH7ssNW0K8G4Td2xO06dp1mL4SCA2LA6ydHZmAP2UZvO46Tg9htQK8uIrQy61
Lba9q7OZNFJmPSKW6lDuaEXnYYI8/Cufxw8080kVx2aTmCDi5s8FRyrbUEVAtxly
gLYq+2/vx8wqzw9BH1QKFes+yjhqQ+CiF1BPDy+jrrMDne3mtb3LZZRjUPOu4wBy
KS5XL/JUEqjB/3bOawE2wPREnOL0x0jrDyrbgKSS9BSdbihiwY8pYpf0rGuV85jy
0GsMTtd/EVPI/1gDpaGit1bU/Kh+fXx7aSyVf24hFZqOaN+eN54KaDt8XRfZR6Dp
uQIDAQAB
-----END PUBLIC KEY-----
`;
const jwkResponse = {
  keys: [
    {
      alg: 'RS256',
      e: 'AQAB',
      kid: '0utUHsLyqVfRPqgzNdOSadJPOURwef8gQcfdOJPZYe4=',
      kty: 'RSA',
      n: 'l8HFKtYH5ZdYrlLQ8qUrb9G9ugbqmse85LyWHbIe17PTlAnW18nWpDHtRfId7QkTGu91B9iXdH2_az9CcRaVmfUVIDVFJR2nCFYjc-_zeVsPzk_xL7tpIGhl0vN-zy6tuNyafX_IWH96xGhpy2ZjDyMnO5qrZcrTwlh0dLlkUYw86me9F6U4pKAo2EXYYqiSado4oYl_YtExC2LSDObI79Be1jaQJuHV7Z9knQ4-RGUwADhmLWZ60qq2MuewKrGuCzUcxZnrAOihwV5rEv16pvLgw-ydOdWQqTAPoH7LH7X5KRPcEtVZbzph3ng7KIqvlPR-qdQUT3PTqBSbRTUTyQ',
      use: 'sig'
    },
    {
      alg: 'RS256',
      e: 'AQAB',
      kid: '9OMIfBqkhYhwAz6edfIa3J679qgBhIiHH6fIpAVGb7Y=',
      kty: 'RSA',
      n: 'iULGOd7nqw3qfpCkX2r7OQ3sH7ssNW0K8G4Td2xO06dp1mL4SCA2LA6ydHZmAP2UZvO46Tg9htQK8uIrQy61Lba9q7OZNFJmPSKW6lDuaEXnYYI8_Cufxw8080kVx2aTmCDi5s8FRyrbUEVAtxlygLYq-2_vx8wqzw9BH1QKFes-yjhqQ-CiF1BPDy-jrrMDne3mtb3LZZRjUPOu4wByKS5XL_JUEqjB_3bOawE2wPREnOL0x0jrDyrbgKSS9BSdbihiwY8pYpf0rGuV85jy0GsMTtd_EVPI_1gDpaGit1bU_Kh-fXx7aSyVf24hFZqOaN-eN54KaDt8XRfZR6DpuQ',
      use: 'sig'
    }
  ],
};


describe('getUserPoolUri', () => {
  // sometimes i wonder why i write tests for these types of functions
  test('Creates a URI', () => {
    const cognitoInfo = {
      region: 'us-never-52',
      userPoolId: 'abcde-12345',
    };
    expect(getUserPoolUri(cognitoInfo)).toBe('https://cognito-idp.us-never-52.amazonaws.com/abcde-12345');
  });
});

describe('getPem', () => {
  beforeAll(() => {
    jwks.getJwks = jest.fn(async () => jwkResponse);
  });

  afterAll(() => {
    jwks.getJwks.mockRestore();
  });

  test('returns null when it cannot find the key', async () => {
    const pem = await getPem('some-uri', 'some-fun-key-that-is-not-real');
    expect(pem).toBe(null);
  });

  test('returns the pem on a successful lookup', async () => {
    const pem = await getPem('some-uri', '9OMIfBqkhYhwAz6edfIa3J679qgBhIiHH6fIpAVGb7Y=');
    expect(pem).toBe(knownPem);
  });
});

describe('validateJwt', () => {
  test('Throws an error if no JWT is provided', async () => {
    await expect(validateJwt())
    .rejects
    .toThrow('No JWT provided');
  });

  test('Throws an error if token passed in is not a JWT', async () => {
    await expect(validateJwt('not a token'))
    .rejects
    .toThrow('Invalid JWT: not a token');
  });
});
