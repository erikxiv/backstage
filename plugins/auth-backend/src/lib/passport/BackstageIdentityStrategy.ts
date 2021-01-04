import { Request } from 'express';
import { JWK, JWT, JWKS, JWKECKey } from 'jose';
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
import { TokenIssuer } from '../../identity';
import { PassportDoneCallback } from './PassportStrategyHelper';
import { BackstageIdentity } from '../../providers';

type Configuration = {
  // Value of the issuer claim in issued tokens
  issuer: string;
  // TokenIssuer to retrieve signing keys from
  tokenIssuer: TokenIssuer;
};

// export const configureMiddleware = (c: Configuration) => (config = c);

export const createBackstageIdentityStrategy = (config: Configuration) => {
  let keyStore: JWKS.KeyStore;
  let keyStoreUpdated: number;
  return new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKeyProvider: async (
        _request: Request,
        rawJwtToken: string,
        done: PassportDoneCallback<string>,
      ) => {
        const { header, payload } = JWT.decode(rawJwtToken, {
          complete: true,
        }) as {
          header: { kid: string };
          payload: { iat: number };
        };
        // Refresh signing keys from identity if needed
        if (!keyStore || (payload?.iat && payload.iat > keyStoreUpdated)) {
          const now = Date.now() / 1000;
          const publicKeys: {
            keys: JWKECKey[];
          } = ((await config.tokenIssuer.listPublicKeys()) as unknown) as {
            keys: JWKECKey[];
          };
          keyStore = new JWKS.KeyStore(
            publicKeys.keys.map(key => JWK.asKey(key)),
          );
          keyStoreUpdated = now;
        }
        // Get key that matches token
        const key: JWK.Key = keyStore.get({ kid: header.kid }) as JWK.Key;
        if (key) {
          return done(undefined, key.toPEM());
        }
        return done(new Error('No public key matching JWT found'));
      },
      algorithms: ['ES256'],
      audience: 'backstage',
      // TODO: How to handle initial setup to ensure this value exists?
      issuer: config?.issuer,
      passReqToCallback: true,
    },
    (
      req: Request,
      jwt_payload: { sub: string },
      done: PassportDoneCallback<BackstageIdentity>,
    ) => {
      // JWT was verified successfully.
      // Pass BackstageIdentity to callback (to be forwarded in req.user)
      done(undefined, {
        id: jwt_payload.sub,
        idToken: ExtractJwt.fromAuthHeaderAsBearerToken()(req),
      });
    },
  );
};
