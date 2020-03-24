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
    const result = await handler({token: 'eyJraWQiOiJqd05UbEc5UFRhT29IbUV0Q0ZiK3p3ZGEzb0RzVEFjZllvMWlURm5UaUZnPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwZGVlZWQzMy05ZmU5LTRhMGQtOWMwYy0yYjlmYjI0NTIxMzgiLCJkZXZpY2Vfa2V5IjoiYXAtbm9ydGhlYXN0LTJfNWFmMjE2OTItYmMwOS00NzIwLTkwMTctYTQ1MDZhN2EwNzJiIiwiZXZlbnRfaWQiOiIxZGI5YWQ4Zi01ZjY5LTRhYzktOTFkMy01ZWRmYjVlODA4ZTkiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNTg1MDQ2NTY5LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtbm9ydGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtbm9ydGhlYXN0LTJfOFdNSDVEQ3JiIiwiZXhwIjoxNTg1MDUwMTY5LCJpYXQiOjE1ODUwNDY1NjksImp0aSI6IjI3ZjViNTU3LWJiY2UtNDkzYS05MDUwLTNlMDE0MDRmZDkxZiIsImNsaWVudF9pZCI6IjJjbjExa292ZmhibW1iNGdtN2g4bWs5ZjNuIiwidXNlcm5hbWUiOiJnc29uIn0.odWctCgiXXJFMxPS88eW3D0paWuEB1ExvLKRwbPNbNqVCgXmM_SrIc23GGAiwva70wo1HIhpS2q9Cs1RbJyWjKJJAILKQjsTjKdAFjTxeOeQ5heIwh8uE8e7wRZCdbbRH_AovnE4r90mqQ80HBjyo8xG9xHVWAGJk7IzH-z_Ltf1wpo8FWURcYCX5tPJ2zSDLC3mXFPdLj_v37ovPMT4qYxJLw-4M8bukMSJXOXY0ClItUD2wycsTbjBQLu0QNU2i2g6IRSvDO1oxDGHU_2AFo6OXWWcy87QWfGsg3zIbbyU4FoQ5_iO3HrjP76y6fgZ_i4M8X7CY74gUxA4xDRDOQ'});
    console.log(result);
  } catch (err) {
    console.log(`valid error`, err);
  }
})();