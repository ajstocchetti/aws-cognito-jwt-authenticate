const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const priKey = fs.readFileSync(path.resolve(__dirname, './jwtRS256.key'), 'utf-8');
const pubKey = fs.readFileSync(path.resolve(__dirname, './jwtRS256.key.pub'), 'utf-8');

const teskJwk = {
  "kty": "RSA",
  "n": "wtUitPhoSb3ByZ77smmzJJufe34EAhjBQ9mKAHVMafF9VU_t41ynE1OT_XsicSWqS8EymP6A4sgUBMivRj6QD_sm1mMdR6K8d1uQyFI8zD4jsNU1CrUkF-YLNR0bwFXLqLWmOR8JgSlfBIkHazR_-AhY_uCy2wbtXTPupSgqlo-XESZq4XKenBcuMqfLyuNqhkBYwHD1qUlHpkI_4JjnAHA4i7kEtVTgoZlXqzsGrfWbM-t0obl9MjMd6EjraVlhCOVIi2HhGCWJBEMxM7cnYueBmusSuG6V_-WcyAda6aSnnzT7djAe7aLybJA57h29uTB99upVVwyIxZao5-bexh-2cDQFKUcKa1_f3WQXLoUQjYSSAhlIDNx9dVwh6Jh3yp-UURmLjxF5xjvYC5hfCgb9TH6RYGu4jI-NyAZTv_7bD0Roqe8lOXKsyEJ5ZQ1gS8LzQb5hiTpBXn4zgAkAa__gHE_lM-rVX63Hj208Fj_wG18pypWjcXlvR3t7TLuXAlSJUkbAOHkoLHaUBg4Jrhc0En05PelzUvoEyEcAm1--92OTXA4EN4R_EKuABuimp8vuo21rvV03RQLPwMbTJSmdDrCcDfQ-90nee4obadGrEvMuERfTpMGA7Zc9sLwrVpx066W3a-iKOdzz1VIvwly_woAy3M3J-OXr8Zkd8u0",
  "e": "AQAB",
  "alg": "RS256",
  "kid": "cognito-util-tests",
  "use": "sig"
};


function sign(payload, useTestKeyId) {
  const keyid = useTestKeyId ? 'cognito-util-tests' : 'some-other-key';
  const options = {
    algorithm: 'RS256',
    keyid: keyid,
  };
  return jwt.sign(payload, priKey, options);
}

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
    teskJwk,
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

module.exports = {
  sign,
  pubKey,
  priKey,
  teskJwk,
  jwkResponse,
};
