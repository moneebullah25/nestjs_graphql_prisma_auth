import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { JwtPayloadWithRefreshToken } from '../types';
import {Request} from "express";

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(public config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('REFRESH_TOKEN_SECRET'),
      passReqToCall: true,
    });
  }

  async validate(req: Request, payload: JwtPayloadWithRefreshToken) {
    const refreshToken = req
      ?.get('authorization')
      ?.replace('Bearer ', '')
      .trim();

    console.log(payload);
    return {...payload, refreshToken};
  }
}
