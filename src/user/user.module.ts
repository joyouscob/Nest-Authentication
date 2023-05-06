import {
  Module,
  NestModule,
  MiddlewareConsumer,
  RequestMethod,
} from '@nestjs/common';

import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { UserMiddleware } from './middlewares/user/user.middleware';
import { BlacklistMiddleware } from './middlewares/blacklist/blacklist.middleware';
import { EmailModule } from '../email/email.module';
@Module({
  imports: [
    EmailModule,
    // CacheModule.register({
    //   store: redisStore as unknown as CacheStore,
    //   host: 'localhost',
    //   port: 6379,
    // }),
    TypeOrmModule.forFeature([User]),
    JwtModule.register({
      secret: jwtConstants.secret,
      signOptions: { expiresIn: '1w' },
    }),
  ],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(UserMiddleware).forRoutes(
      {
        path: 'user',
        method: RequestMethod.GET,
      },
      {
        path: 'user/refresh',
        method: RequestMethod.POST,
      },
    );
    consumer.apply(BlacklistMiddleware).forRoutes({
      path: 'user/logout',
      method: RequestMethod.POST,
    });
  }
}
