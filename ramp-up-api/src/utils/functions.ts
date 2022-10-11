import * as jwt from "jsonwebtoken";
import { Response } from "express";
import { User } from "../entity/User";

export const validateToken = (
  userData: User,
  res: Response,
  refresh: boolean
) => {
  let payload = null;
  try {
    payload = jwt.verify(userData.token, process.env.TOKEN_KEY as string);
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    if (Date.now() >= payload.exp * 1000) {
      res.status(400).send({ token: "Token has expired", status: 400 });
      payload = null;
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
    } else if (refresh && !payload.loggedIn) {
      res.status(400).send({ token: "User has signed out", status: 400 });
      payload = null;
    } else if (refresh) {
      res.status(200).send({ token: userData.token, status: 200 });
    }
  } catch (err) {
    res.status(400).send({ token: "Invalid Token", status: 400 });
    payload = null;
  }
  return payload;
};
