import { Request } from 'express';
import { JWK, JWT, JWKS } from 'jose';
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
import { PassportDoneCallback } from './PassportStrategyHelper';
import { BackstageIdentity } from '../../providers';
import { IdentityClient } from '../../identity';
import { PluginEndpointDiscovery } from '@backstage/backend-common';

export const createBackstageIdentityStrategy = async (
  discovery: PluginEndpointDiscovery,
) => {
  const client: IdentityClient = new IdentityClient({ discovery });
  const issuer = await discovery.getExternalBaseUrl('auth');
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
          const publicKeys = await client.listPublicKeys();
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
      issuer,
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
