import { User } from "../entity/User";
import { Request, Response } from "express";
import * as crypto from "crypto";
import * as jwt from "jsonwebtoken";
import * as userService from "../services/users";
import { validateToken } from "../utils/functions";

export const addUser = async (req: Request, res: Response) => {
  const { username, password, role } = req.body.payload;
  const userData = await userService.findUser(username);
  if (userData instanceof Error) {
    res.send({ error: (userData as Error).message });
  } else {
    if (userData) {
      res.send({ error: "User already exists" });
    } else {
      const newUser = new User();
      newUser.username = username;
      const salt = crypto.randomBytes(16);
      crypto.pbkdf2(
        password,
        salt,
        310000,
        32,
        "sha256",
        async function (err, hashedPassword) {
          newUser.password = hashedPassword.toString("base64");
          newUser.salt = salt.toString("base64");
          newUser.token = jwt.sign(
            {
              userName: username,
              password: newUser.password,
              role: role,
              loggedIn: true,
            },
            process.env.TOKEN_KEY as string,
            {
              expiresIn: "2h",
            }
          );
          try {
            await userService.createUser(newUser);
            res.send({ ...newUser, role: role });
          } catch {
            res.send({ error: "Could not sign up" });
          }
        }
      );
    }
  }
};

export const getUser = async (req: Request, res: Response) => {
  const { username, password } = req.body.payload;
  const userData = await userService.findUser(username);
  if (userData instanceof Error) {
    res.send({ error: (userData as Error).message });
  } else {
    if (userData) {
      crypto.pbkdf2(
        password,
        Buffer.from(userData.salt as string, "base64"),
        310000,
        32,
        "sha256",
        async function (err, hashedPassword) {
          if (
            crypto.timingSafeEqual(
              Buffer.from(userData.password as string, "base64"),
              hashedPassword
            )
          ) {
            let role = "";
            const payload = validateToken(userData, res, false);
            if (payload != null) {
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-ignore
              role = payload.role;
              userData.token = jwt.sign(
                {
                  userName: username,
                  password: userData.password,
                  role: role,
                  loggedIn: true,
                },
                process.env.TOKEN_KEY as string,
                {
                  expiresIn: "2h",
                }
              );
              try {
                await userService.updateUser(username, userData);
                res.send({ ...userData, role: role });
              } catch (err) {
                res.send({ error: "Could not sign in" });
              }
            }
          } else {
            res.send({ error: "Incorrect password" });
          }
        }
      );
    } else {
      res.send({ error: "User does not exist" });
    }
  }
};

export const refreshUser = async (req: Request, res: Response) => {
  const userName = req.body.payload;
  const userData = await userService.findUser(userName);
  if (userData instanceof Error) {
    res.status(400).send({ token: (userData as Error).message, status: 400 });
  } else {
    if (userData) {
      validateToken(userData, res, true);
    }
  }
};

export const signOutUser = async (req: Request, res: Response) => {
  const userName = req.body.payload;
  const userData = await userService.findUser(userName);
  if (userData instanceof Error) {
    res.status(400).send({ error: (userData as Error).message });
  } else {
    if (userData) {
      const payload = validateToken(userData, res, false);
      if (payload != null) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const role = payload.role;
        userData.token = jwt.sign(
          {
            userName: userName,
            password: userData.password,
            role: role,
            loggedIn: false,
          },
          process.env.TOKEN_KEY as string
        );
        try {
          await userService.updateUser(userName, userData);
          res.status(400).send({ error: "User signed out" });
        } catch (err) {
          res.status(400).send({ error: "Error signing out user" });
        }
      }
    }
  }
};
