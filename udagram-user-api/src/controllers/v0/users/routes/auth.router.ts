import {Router, Request, Response} from 'express';

import {User} from '../models/User';
import * as c from '../../../../config/config';

import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import {NextFunction} from 'connect';

import * as EmailValidator from 'email-validator';

const router: Router = Router();

const EMAIL_REQ = 'Email is required or malformed.';
const PASSWD_REQ = 'Password is required.';
const USER_NF = 'User was not found..';
const PASSWD_INV = 'Password was invalid.';
const EMAIL_MIS = 'Email is missing or malformed.';
const USER_EXISTS = 'User already exists.';

async function generatePassword(plainTextPassword: string): Promise<string> {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(plainTextPassword, salt);
}

async function comparePasswords(plainTextPassword: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(plainTextPassword, hash);
}

function generateJWT(user: User): string {
  return jwt.sign(user.short(), c.config.jwt.secret);
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.headers || !req.headers.authorization) {
    return res.status(401).send({message: 'No authorization headers.'});
  }

  const tokenBearer = req.headers.authorization.split(' ');
  if (tokenBearer.length != 2) {
    return res.status(401).send({message: 'Malformed token.'});
  }

  const token = tokenBearer[1];
  return jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
    if (err) {
      return res.status(500).send({auth: false, message: 'Failed to authenticate.'});
    }
    return next();
  });
}

router.get('/verification',
    requireAuth,
    async (req: Request, res: Response) => {
      return res.status(200).send({auth: true, message: 'Authenticated.'});
    });

router.post('/login', async (req: Request, res: Response) => {
  const email = req.body.email;
  const password = req.body.password;

  log(req, "Login attempt");

  if (!email || !EmailValidator.validate(email)) {
    log(req, EMAIL_REQ);
    return res.status(400).send({auth: false, message: EMAIL_REQ});
  }

  if (!password) {
    log(req, PASSWD_REQ);
    return res.status(400).send({auth: false, message: PASSWD_REQ});
  }

  const user = await User.findByPk(email);
  if (!user) {
    log(req, USER_NF);
    return res.status(401).send({auth: false, message: USER_NF});
  }

  const authValid = await comparePasswords(password, user.passwordHash);

  if (!authValid) {
    log(req, PASSWD_INV);
    return res.status(401).send({auth: false, message: PASSWD_INV});
  }

  const jwt = generateJWT(user);
  log(req, "Login successful");

  res.status(200).send({auth: true, token: jwt, user: user.short()});
});


router.post('/', async (req: Request, res: Response) => {
  const email = req.body.email;
  const plainTextPassword = req.body.password;

  log(req, `Creating user: ${email}`);

  if (!email || !EmailValidator.validate(email)) {
    log(req, EMAIL_MIS);
    return res.status(400).send({auth: false, message: EMAIL_MIS});
  }

  if (!plainTextPassword) {
    log(req, PASSWD_REQ);
    return res.status(400).send({auth: false, message: PASSWD_REQ});
  }

  const user = await User.findByPk(email);
  if (user) {
    log(req, USER_EXISTS);
    return res.status(422).send({auth: false, message: USER_EXISTS});
  }

  const generatedHash = await generatePassword(plainTextPassword);

  const newUser = await new User({
    email: email,
    passwordHash: generatedHash,
  });

  const savedUser = await newUser.save();
  log(req, `User created: ${email}`);

  const jwt = generateJWT(savedUser);
  res.status(201).send({token: jwt, user: savedUser.short()});
});

router.get('/', async (req: Request, res: Response) => {
  res.send('auth');
});

function log(req: Request, message: string) {
  console.log(`${new Date().toISOString()} [${req.requestId}] ${message}`);
}

export const AuthRouter: Router = router;
