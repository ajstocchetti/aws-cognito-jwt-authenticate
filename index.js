const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const axios = require('axios');
const jwk = require('./jwk.js');

// see http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html

module.exports = {
  validateJwt,
  getUserPoolUri,
  getPem,
}

async function validateJwt(token, cognitoArray) {
  // Fail if there is no token
  if (!token) {
    throw new Error('No JWT provided');
  }

  // Fail if the token is not a jwt
  const decodedJwt = jwt.decode(token, { complete: true });
  if (!decodedJwt) {
    throw new Error(`Invalid JWT: ${token}`);
  }

  // Fail if token is not from allowed User Pool
  const issuer = decodedJwt.payload.iss;
  // allow passing in a single cognito details object
  if (!Array.isArray(cognitoArray)) cognitoArray = [cognitoArray];
  const allowedIssuers = cognitoArray.map(getUserPoolUri);
  if (!allowedIssuers.includes(issuer)) {
    throw new Error(`Provided Token not from allowed UserPool: iss = ${issuer}`);
  }

  // Reject the jwt if it's not an 'Identity Token'
  if (decodedJwt.payload.token_use != 'id') {
    throw new Error(`Provided Token is not an identity token: ${decodedJwt.payload.token_use}`);
  }

  // Reject if JWK is not valid
  const pem = getPem(issuer, decodedJwt.header.kid);
  if (!pem) {
    throw new Error('Invalid JSON Web Key');
  }

  // Reject if invalid signature
  // (jwt.verify will throw an error if the token is invalid)
  return jwt.verify(token, pem, { issuer });
}


function getUserPoolUri({userPoolId, region}) {
  return `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
}

async function getPem(userPoolURI, keyId) {
  // TODO: cache these somehow
  const jwks = await jwk.getJwks(userPoolURI);
  const keys = jwks.keys.filter(key => key.kid === keyId);
  return keys[0] ? jwkToPem(keys[0]) : null;
}
