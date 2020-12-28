import { JWK, JWT, JWKS } from 'jose';
import { TokenIssuer, AnyJWK } from '../identity';
import { Request, Response, NextFunction } from 'express';

type Configuration = {
  /** Value of the issuer claim in issued tokens */
  issuer: string;
  /** TokenIssuer to retrieve public keys from */
  tokenIssuer: TokenIssuer;
};

let config: Configuration;

export const configureMiddleware = (c: Configuration) => (config = c);

export const middleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (
    !req.headers.authorization ||
    !req.headers.authorization.startsWith('Bearer ')
  ) {
    res.status(401).send(`Unauthorized`);
    return;
  }
  const token = req.headers.authorization.substring(7);
  const publicKeys: AnyJWK[] = await config.tokenIssuer.listPublicKeys();
  const keyStore = new JWKS.KeyStore(
    publicKeys.keys.map(key => JWK.asKey(key)),
  );
  try {
    const decoded = JWT.IdToken.verify(token, keyStore, {
      algorithms: ['ES256'],
      audience: 'backstage',
      issuer: config.issuer,
    });
    // Verified, add BackstageIdentity to req.user
    req.user = {
      id: decoded.sub,
      idToken: token,
    };
    next();
  } catch (error) {
    // JWT verification failed
    // Do not leak validation failure cause to client
    // console.log('jwt verification failed', enrror);
    res.status(401).send(`Unauthorized`);
  }
};
