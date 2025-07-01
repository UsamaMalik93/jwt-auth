import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { UserService } from 'src/user/use.service';
import { UserDocument, User } from 'src/user/user.model';
import { JwtPayload } from 'src/common/jwt-payload.interface';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) { }

    async register(registerDto: RegisterDto): Promise<{ user: UserDocument; tokens: any }> {
        try {
            const user = await this.userService.create(registerDto);
            const tokens = await this.generateTokens(user);
            await this.userService.updateRefreshToken(user._id.toString(), tokens.refreshToken);

            return { user, tokens };
        } catch (error) {
            if (error instanceof ConflictException) {
                throw error;
            }
            throw new Error('Registration failed');
        }
    }

    async login(loginDto: LoginDto): Promise<{ user: UserDocument; tokens: any }> {
        const user = await this.validateUser(loginDto.email, loginDto.password);
        const tokens = await this.generateTokens(user);
        await this.userService.updateRefreshToken(user._id.toString(), tokens.refreshToken);

        return { user, tokens };
    }

    async logout(userId: string): Promise<void> {
        await this.userService.updateRefreshToken(userId, null);
    }

    async refreshTokens(userId: string, refreshToken: string): Promise<any> {
        const user = await this.userService.findById(userId);
        const isValidRefreshToken = await this.userService.validateRefreshToken(userId, refreshToken);

        if (!isValidRefreshToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const tokens = await this.generateTokens(user);
        await this.userService.updateRefreshToken(user._id.toString(), tokens.refreshToken);

        return tokens;
    }

    private async validateUser(email: string, password: string): Promise<UserDocument> {
        const user = await this.userService.findByEmail(email);

        if (!user || !user.isActive) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const isPasswordValid = await this.userService.validatePassword(user, password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        return user;
    }

    private async generateTokens(user: UserDocument): Promise<{ accessToken: string; refreshToken: string }> {
        const payload: JwtPayload = {
            _id: user._id.toString(),
            email: user.email,
            roles: user.role,
        };

        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(payload, {
                secret: this.configService.get<string>('jwt.secret'),
                expiresIn: this.configService.get<string>('jwt.expiresIn'),
            }),
            this.jwtService.signAsync(payload, {
                secret: this.configService.get<string>('jwt.refreshSecret'),
                expiresIn: this.configService.get<string>('jwt.refreshExpiresIn'),
            }),
        ]);

        return { accessToken, refreshToken };
    }
}