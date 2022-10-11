import { Controller, Get, Patch, Post, Req, Res } from '@nestjs/common';
import { UsersService } from './users.service';
import { Request, Response } from 'express';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { UserDto } from '../dto/user.dto';
import { validatorDto } from '../utils/dtoValidator';
import { ConfigService } from '@nestjs/config';
import { validateToken } from '../utils/functions';

@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private configService: ConfigService,
  ) {}

  @Post('/add')
  async addUser(@Req() req: Request, @Res() res: Response): Promise<any> {
    const { username, password, role } = req.body.payload;
    const userData = await this.usersService.findUser(username);
    if (userData instanceof Error) {
      res.status(400).send({ error: (userData as Error).message });
    } else {
      if (userData) {
        res.status(400).send({ error: 'User already exists' });
      } else {
        const key = this.configService.get<string>('TOKEN_KEY');
        const newUser = new UserDto();
        newUser.username = username;
        const salt = crypto.randomBytes(16);
        crypto.pbkdf2(
          password,
          salt,
          310000,
          32,
          'sha256',
          async (err, hashedPassword) => {
            newUser.password = hashedPassword.toString('base64');
            newUser.salt = salt.toString('base64');

            newUser.token = jwt.sign(
              {
                userName: username,
                password: newUser.password,
                role: role,
                loggedIn: true,
              },
              key,
              {
                expiresIn: '2h',
              },
            );
            try {
              await validatorDto(UserDto, newUser);
              try {
                await this.usersService.createUser(newUser);
                res.status(200).send({ ...newUser, role: role });
              } catch {
                res.status(400).send({ error: 'Could not sign up' });
              }
            } catch (e) {
              return res.status(400).send({ error: (e as TypeError).message });
            }
          },
        );
      }
    }
  }

  @Post('/get')
  async getUser(@Req() req: Request, @Res() res: Response): Promise<any> {
    const { username, password } = req.body.payload;
    const userData = await this.usersService.findUser(username);
    if (userData instanceof Error) {
      res.status(400).send({ error: (userData as Error).message });
    } else {
      if (userData) {
        const key = this.configService.get<string>('TOKEN_KEY');
        crypto.pbkdf2(
          password,
          Buffer.from(userData.salt as string, 'base64'),
          310000,
          32,
          'sha256',
          async (err, hashedPassword) => {
            if (
              crypto.timingSafeEqual(
                Buffer.from(userData.password as string, 'base64'),
                hashedPassword,
              )
            ) {
              let role = '';
              const payload = validateToken(userData, res, false);
              if (payload != null) {
                role = payload.role;
                userData.token = jwt.sign(
                  {
                    userName: username,
                    password: userData.password,
                    role: role,
                    loggedIn: true,
                  },
                  key,
                  {
                    expiresIn: '2h',
                  },
                );
                try {
                  await validatorDto(UserDto, userData);
                  try {
                    await this.usersService.updateUser(username, userData);
                    res.status(200).send({ ...userData, role: role });
                  } catch (err) {
                    console.log(err);
                    res.status(400).send({ error: 'Could not sign in' });
                  }
                } catch (e) {
                  return res
                    .status(400)
                    .send({ error: (e as TypeError).message });
                }
              }
            } else {
              res.status(400).send({ error: 'Incorrect password' });
            }
          },
        );
      } else {
        res.status(400).send({ error: 'User does not exist' });
      }
    }
  }

  @Post('/refresh')
  async refreshUser(@Req() req: Request, @Res() res: Response) {
    const userName = req.body.payload;
    const userData = await this.usersService.findUser(userName);
    if (userData instanceof Error) {
      res.status(400).send({ token: (userData as Error).message, status: 400 });
    } else {
      if (userData) {
        validateToken(userData, res, true);
      }
    }
  }

  @Patch('/signout')
  async signOutUser(@Req() req: Request, @Res() res: Response) {
    const userName = req.body.payload;
    const userData = await this.usersService.findUser(userName);
    if (userData instanceof Error) {
      res.status(400).send({ error: (userData as Error).message });
    } else {
      if (userData) {
        const key = this.configService.get<string>('TOKEN_KEY');
        const payload = validateToken(userData, res, false);
        if (payload != null) {
          const role = payload.role;
          userData.token = jwt.sign(
            {
              userName: userName,
              password: userData.password,
              role: role,
              loggedIn: false,
            },
            key,
          );
          try {
            await validatorDto(UserDto, userData);
            try {
              await this.usersService.updateUser(userName, userData);
              res.status(200).send('User signed out');
            } catch (err) {
              res.status(400).send({ error: 'Error signing out user' });
            }
          } catch (e) {
            return res.status(400).send({ error: (e as TypeError).message });
          }
        }
      }
    }
  }
}
