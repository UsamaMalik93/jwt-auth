import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import jwtConfig from 'src/config/jwt.config';
import { UsersModule } from 'src/user/user.module';
@Module({
    imports: [
      ConfigModule.forFeature(jwtConfig),
      PassportModule,
      JwtModule.register({}),
      UsersModule,
    ],
    controllers: [],
    providers: [AuthService, JwtStrategy],
    exports: [AuthService],
  })
  export class AuthModule {}