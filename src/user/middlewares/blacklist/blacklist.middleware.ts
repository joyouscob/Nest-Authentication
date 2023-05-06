import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable, NestMiddleware } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Cache } from 'cache-manager';

@Injectable()
export class BlacklistMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async use(req: any, res: any, next: () => void) {
    // const getRefreshToken = req.cookies['refresh_token'];

    // const decodedRefreshToken = await this.jwtService.decode(getRefreshToken);
    // const expiry = decodedRefreshToken['exp'];

    // //check for difference in today and token expiration date in seconds
    // const expiryDate: any = new Date(expiry * 1000);
    // const today: any = new Date();
    // const dateDifferenceInSeconds: number = Math.abs(expiryDate - today) / 1000;
    // console.log(dateDifferenceInSeconds, 'seconds');
    // //write data to redis to blacklist
    // await this.cacheManager.set(
    //   getRefreshToken,
    //   getRefreshToken,
    //   dateDifferenceInSeconds,
    // );

    // console.log(await this.cacheManager.get(getRefreshToken), 'Blacklisted');

    next();
  }
}
