const auth = require('./index.js');
const axios = require('axios');
const helper = require('./tests/helper.js');
const {
  getPem,
  getUserPoolUri,
  validateJwt,
} = auth;

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
    axios.get = jest.fn(async () => ({ data: helper.jwkResponse }));
  });

  afterAll(() => {
    axios.get.mockRestore();
  });

  test('returns null when it cannot find the key', async () => {
    const pem = await getPem('some-uri', 'some-fun-key-that-is-not-real');
    expect(pem).toBe(null);
  });

  test('returns the pem on a successful lookup', async () => {
    const pem = await getPem('some-uri', 'cognito-util-tests');
    expect(pem).toBe(helper.pubKey);
  });
});

describe('validateJwt - failure cases', () => {
  beforeAll(() => {
    axios.get = jest.fn(async () => ({ data: helper.jwkResponse }));
  });

  afterAll(() => {
    axios.get.mockRestore();
  });

  const cognitoDetails = { region: 'us-east-2', userPoolId: 'abcde-12345' };

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

  test('Throws an error if token is not from allowed Cognito User Pool', async () => {
    const token = helper.sign({ iss: 'some random person' });
    await expect(validateJwt(token, cognitoDetails))
    .rejects
    .toThrow('Provided Token not from allowed UserPool: iss = some random person');
  });

  test('Throws an error if token is not identity token', async () => {
    const iss = getUserPoolUri(cognitoDetails);
    const token = helper.sign({ iss, token_use: 'for testing only' });
    await expect(validateJwt(token, cognitoDetails))
    .rejects
    .toThrow('Provided Token is not an identity token: for testing only');
  });

  test('Throws an error if it cannot retreive a PEM for the JWT', async () => {
    const iss = getUserPoolUri(cognitoDetails);
    const token = helper.sign({ iss, token_use: 'id' });
    await expect(validateJwt(token, cognitoDetails))
    .rejects
    .toThrow('Invalid JSON Web Key');
  });
});


describe('validateJwt - success cases', () => {
  beforeAll(() => {
    axios.get = jest.fn(async () => ({ data: helper.jwkResponse }));
  });

  afterAll(() => {
    axios.get.mockRestore();
  });

  const cognitoDetails = { region: 'us-east-2', userPoolId: 'abcde-12345' };
  const iss = getUserPoolUri(cognitoDetails);
  const time = Math.round(Date.now()/1000);
  const tokenPayload = {
    sub: 'subject',
    aud: 'audience',
    iss: iss,
    token_use: 'id',
    'cognito:username': 'util-test',
    auth_time: time,
    iat: time,
    exp: time + 3600,
  };
  const token = helper.sign(tokenPayload, true);

  test('Works with a properly signed JWT', async () => {
    const validated = await validateJwt(token, cognitoDetails);
    expect(validated).toEqual(tokenPayload);
  });

  test('Allows passing in an array of User Pool details', async ()  => {
    const detailsArray = [
      { region: 'us-west-1', userPoolId: '1'},
      { region: 'us-west-2', userPoolId: '2'},
      { region: 'us-east-1', userPoolId: '3'},
      cognitoDetails,
      { region: 'us-west-1', userPoolId: '4'},
    ];
    const validated = await validateJwt(token, detailsArray);
    expect(validated).toEqual(tokenPayload);
  });
});
