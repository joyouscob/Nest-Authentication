import {
  Injectable,
  NestMiddleware,
  Inject,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class UserMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  /* This is the implementation of the `use` method of the `UserMiddleware` class, which is a NestJS
  middleware. The `use` method is called for every incoming request and it takes three parameters:
  `req` (request object), `res` (response object), and `next` (a function that moves the request to
  the next middleware or route handler). */
  async use(req: any, res: any, next: () => void) {
    //get the refresh token and check if its not blacklisted
    const getRefreshToken = req.cookies['refresh_token'];
    const getToken = req.header('Authorization').replace('Bearer ');
    console.log(getToken, await this.cacheManager.get(getToken), 'Token');
    console.log(
      getRefreshToken,
      await this.cacheManager.get(getRefreshToken),
      'Refresh Token',
    );
    if (await this.cacheManager.get(getRefreshToken)) {
      throw new HttpException('Blacklisted token', HttpStatus.UNAUTHORIZED);
    }
    if (await this.cacheManager.get(getToken)) {
      throw new HttpException('Blacklisted token', HttpStatus.UNAUTHORIZED);
    }
    if (!getToken && !getRefreshToken) {
      throw new HttpException('No token provided', HttpStatus.UNAUTHORIZED);
    }

    next();
  }
}
