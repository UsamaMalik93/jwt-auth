import { Injectable, UnauthorizedException, ConflictException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { UserService } from 'src/user/use.service';
import { UserDocument, User } from 'src/user/user.model';
import { JwtPayload } from 'src/common/jwt-payload.interface';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Body, Controller, Post } from '@nestjs/common';

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
            // Send email verification (placeholder)
            if (user.emailVerificationToken) {
                console.log(`Send verification email to ${user.email} with link: http://your-app/verify-email?token=${user.emailVerificationToken}`);
            }
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
        const user = await this.userService.findByEmail(loginDto.email);
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
        if (!user.emailVerified) {
            throw new UnauthorizedException('Please verify your email before logging in.');
        }

        // Check if account is locked
        if (user.lockUntil && user.lockUntil > new Date()) {
            throw new UnauthorizedException('Account is temporarily locked due to too many failed login attempts. Please try again later.');
        }

        const isPasswordValid = await this.userService.validatePassword(user, loginDto.password);
        if (!isPasswordValid) {
            await this.userService.incrementLoginAttempts(user);
            throw new UnauthorizedException('Invalid credentials');
        }

        // Reset login attempts and lockUntil on successful login
        await this.userService.resetLoginAttempts(user);
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

    async requestPasswordReset(email: string): Promise<void> {
        const user = await this.userService.findByEmail(email);
        if (!user) return; // Do not reveal if user exists
        // Generate token
        const token = (Math.random().toString(36).substr(2) + Date.now().toString(36));
        const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        await this.userService.setPasswordResetToken(user._id.toString(), token, expires);
        // Placeholder for sending email
        console.log(`Send email to ${email} with reset link: http://your-app/reset-password?token=${token}`);
    }

    async resetPassword(token: string, newPassword: string): Promise<void> {
        // Password strength validation
        const strong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/.test(newPassword);
        if (!strong) {
            throw new BadRequestException('Password too weak. Must be at least 8 characters, include uppercase, lowercase, number, and special character.');
        }
        const user = await this.userService.findByResetToken(token);
        if (!user || !user.passwordResetExpires || user.passwordResetExpires < new Date()) {
            throw new UnauthorizedException('Invalid or expired reset token');
        }
        await this.userService.updatePassword(user._id.toString(), newPassword);
        await this.userService.clearPasswordResetToken(user._id.toString());
    }

    async verifyEmail(token: string): Promise<void> {
        const user = await this.userService.findByEmailVerificationToken(token);
        if (!user || !user.emailVerificationExpires || user.emailVerificationExpires < new Date()) {
            throw new UnauthorizedException('Invalid or expired verification token');
        }
        await this.userService.verifyEmail(user._id.toString());
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

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    async login(@Body() loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @Post('request-password-reset')
    async requestPasswordReset(@Body('email') email: string) {
        await this.authService.requestPasswordReset(email);
        return { message: 'If that email is registered, a password reset link has been sent.' };
    }

    @Post('reset-password')
    async resetPassword(@Body() body: { token: string; newPassword: string }) {
        await this.authService.resetPassword(body.token, body.newPassword);
        return { message: 'Password has been reset successfully.' };
    }

    @Post('verify-email')
    async verifyEmail(@Body('token') token: string) {
        await this.authService.verifyEmail(token);
        return { message: 'Email verified successfully.' };
    }
}