import { Express, Request, Response, NextFunction } from 'express'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
dotenv.config()

type User = {
  username : string,
  session: string,
  timestamp: number
}

declare global {
  namespace Express {
      export interface Request {
          user? : User
      }
  }
}

var _loginUrl : string;
function initCookieAuth(app : Express, loginUrl : string) {
  _loginUrl = loginUrl;
  app.use(cookieParser(process.env.SECRET));
  app.use(setUserInfo);
}

function signInUser(res : Response, username : string, sessionId : string) {
  res.cookie('user', username, {
      httpOnly: true
  });
  res.cookie('os', sessionId, {
    signed: true,
    httpOnly: true
  });
  res.cookie('time', Date.now(), {
    signed: true,
    httpOnly: true
  })
}

function changeSession(res: Response, sessionId: string) {
    res.clearCookie('os');
    res.cookie('os', sessionId, {
        signed: true,
        httpOnly: true
    });
    res.clearCookie('time');
    res.cookie('time', Date.now(), {
        signed: true,
        httpOnly: true
    })
}

function signOutUser(res : Response) {
  res.clearCookie('os');
  res.clearCookie('user');
  res.clearCookie('time');
}

function setUserInfo(req : Request, res : Response, next : NextFunction) {    
  const username = req.cookies?.user; 
  const session = req.signedCookies?.os;
  const timestamp = req.signedCookies?.time; 
  if (username && session) { 
    req.user = {      
      username,
      session,
      timestamp
    };
  }
  next(); 
}

function requiresAuthentication(req : Request, res : Response, next : NextFunction) {  
  if (req.user) next();
  else res.redirect(302, `${_loginUrl}`);            
}
  
export {initCookieAuth, signInUser, signOutUser, requiresAuthentication, changeSession};

