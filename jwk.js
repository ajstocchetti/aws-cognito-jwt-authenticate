const axios = require('axios');

module.exports = {
  getJwks,
}

async function getJwks(userPoolURI) {
  const jwtKeySetURI = `${userPoolURI}/.well-known/jwks.json`;
  const response = await axios.get(jwtKeySetURI);
  return response.data;
}
