import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { JwtPayloadWithRefreshToken } from '../types';

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy) {
  constructor(public config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('ACCESS_TOKEN_SECRET'),
      passReqToCall: true,
    });
  }

  async validate(payload: JwtPayloadWithRefreshToken) {
    return payload;
  } 
}
