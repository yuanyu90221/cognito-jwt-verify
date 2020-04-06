import * as Axios from 'axios';
import * as jsonwebtoken from 'jsonwebtoken';
const jwtToPem = require('jwk-to-pem');
import {promisify,inspect} from 'util';
import * as dotenv from 'dotenv';
dotenv.config();

export interface ClaimVerifyRequest {
  readonly token: string;
}
export interface ClaimVerifyResult {
  readonly userName: string;
  readonly clientId: string;
  readonly isValid: boolean;
  readonly error?: any;
}

interface TokenHeader {
  kid: string;
  alg: string;
}

interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

interface PublicKeys {
  keys: PublicKey[];
}

interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}

interface Claim {
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  username: string;
  client_id: string;
  name: string;
  sub: string;
}

const cognitoPoolId = process.env.POOL_USER_ID || '';

const cognitoIssuer = `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${cognitoPoolId}`;

let cacheKeys: MapOfKidToPublicKey | undefined;
const getPublicKeys = async (): Promise<MapOfKidToPublicKey> => {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get<PublicKeys>(url);
    cacheKeys = publicKeys.data.keys.reduce((agg, current)=>{
      const pem = jwtToPem(current);
      agg[current.kid] = {instance: current, pem};
      return agg;
    }, {} as MapOfKidToPublicKey);
    return cacheKeys;
  } else {
    return cacheKeys;
  }
};
const verifyPromised = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

const handler = async (request: ClaimVerifyRequest): Promise<ClaimVerifyResult> => {
  let result: ClaimVerifyResult;
  try {
    console.log(`user claim verify invoked for `, inspect(request));
    const token = request.token;
    const tokenSections = (token || '').split('.');
    if (tokenSections.length < 2) {
      throw new Error(`requested token is invalid`);
    }

    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON) as TokenHeader;
    const keys = await getPublicKeys();
    const key = keys[header.kid];
    if (key === undefined) {
      throw new Error(`claim made for unknown kid`);
    }
    
    const claim = await verifyPromised(token, key.pem) as Claim;
    const currentSeconds = Math.floor( (new Date()).valueOf()/1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
      throw new Error(`claim is expired or invalid`);
    }
    if (claim.iss !== cognitoIssuer) {
      throw new Error(`claim issuer is invalid`);
    }
    console.log(claim);
    // console.log(claim.token_use);
    // if (claim.token_use !== 'access') {
    //   throw new Error(`claim use is not access`);
    // }
    console.log(`claim confirmed for ${claim.username}`);
    result = {userName: claim.username, clientId: claim.client_id, isValid: true};
  } catch (error) {
    result = {userName: '', clientId: '', error, isValid: false};
  }
  return result;
};

(async()=>{
  try {
    const result = await handler({token: 'eyJraWQiOiJoUHlGb2xXSkJianJXc2t6TnlZamx3SFY3RCs4bWVaeXBpTlJXR1BHUE9zPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI4MDdhYTBlZC04NzVmLTQ0MDYtOTU5ZS0xNTg4ODAwOTFmZmMiLCJhdWQiOiIyY24xMWtvdmZoYm1tYjRnbTdoOG1rOWYzbiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0b206c2NvcGUiOiJhZG1pbiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTg2MTY0OTEyLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtbm9ydGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtbm9ydGhlYXN0LTJfOFdNSDVEQ3JiIiwibmFtZSI6Imdzb24iLCJjb2duaXRvOnVzZXJuYW1lIjoiZ3NvbiIsImV4cCI6MTU4NjE2ODUxMiwiaWF0IjoxNTg2MTY0OTEyLCJlbWFpbCI6Impzb25AcnBsYWIuYWkifQ.gguo3P0FPELPkaTj0WGKXqEaa4-DEkznEChEndfdH_olseUqfbcgeJwCxe5sSe89zyTqDcHlnSPWKo1e1eP-eEqxjYKObOdcF98_RH13j6hn1YL5I1lYxvhRAB10YLT38KKkeTHe3VQhAjyqSH0CYjRsIgKEmxLdZ_wIx2E9XAJ9176L_SwKOEDj2xrabfm_7hcF4e_hPKBuGjNjaM5deq2RdPcyl_XyuQQjjTXxYqLLCTqKxQ0Y0_ykO0qVWLzSj7ObaBQThI0iwrEHokLrU-B6VbzXyUlaEyYw6f5r55xNSaQqzkT_vFe3MHDw8fWDbIHN35WO-CnRVzmbmD9uaQ'});
    if (result.error) {
      throw result.error;
    } 
    console.log(result);
    // console.log(inspect(result));
  } catch (err) {
    console.log(`valid error`, err);
  }
})();