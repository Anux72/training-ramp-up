import * as jwt from 'jsonwebtoken';
import { Response } from 'express';
import { User } from '../entity/user.entity';
import { ConfigService } from '@nestjs/config';

export const validateToken = (
  userData: User,
  res: Response,
  refresh: boolean,
) => {
  const key = new ConfigService().get<string>('TOKEN_KEY');
  let payload = null;
  try {
    payload = jwt.verify(userData.token, key);
    if (Date.now() >= payload.exp * 1000) {
      res.status(400).send({ token: 'Token has expired', status: 400 });
      payload = null;
    } else if (refresh && !payload.loggedIn) {
      res.status(400).send({ token: 'User has signed out', status: 400 });
      payload = null;
    } else if (refresh) {
      res.status(200).send({ token: userData.token, status: 200 });
    }
  } catch (err) {
    res.status(400).send({ token: 'Invalid Token', status: 400 });
    payload = null;
  }
  return payload;
};
