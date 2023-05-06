import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';
import { CacheModule, CacheStore } from '@nestjs/cache-manager';
import * as redisStore from 'cache-manager-redis-store';
import { MailerModule } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';
import { ConfigModule } from '@nestjs/config';
import { EmailModule } from './email/email.module';
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MailerModule.forRootAsync({
      useFactory: async () => ({
        transport: process.env.DEVELOPMENT
          ? { host: '0.0.0.0', port: 1025 }
          : process.env.SMTPAUTH,
        defaults: {
          from: '"Odinwo" <noreply@odinwo.com>',
        },
        template: {
          dir: __dirname + '/mail/templates',
          adapter: new EjsAdapter(),
          options: {
            strict: false,
          },
        },
      }),
    }),
    CacheModule.register({
      isGlobal: true,
      // if you use redis
      useFactory: async () => ({
        store: redisStore as any,
        host: 'localhost',
        port: 6379,
        // ttl: 1000,
      }),
    }),

    TypeOrmModule.forRoot({
      type: 'mysql',
      host: '127.0.0.1',
      port: 3306,
      username: 'root',
      password: 'root',
      database: 'nest_auth',
      // entities: [],
      autoLoadEntities: true, //dont use this in production
      synchronize: true,
    }),
    UserModule,
    EmailModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
