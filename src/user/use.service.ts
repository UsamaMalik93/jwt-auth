import { BadRequestException, ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, UserDocument } from "./user.model";
import { Model } from "mongoose";
import * as bcrypt from 'bcryptjs'
import { RegisterDto } from "src/auth/dto/register.dto";
import { CreateUserDto } from "./dto/create-user.dto";
import { randomBytes } from 'crypto';

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name)
        private readonly userModel: Model<UserDocument>

    ) { }

    async create(userDto: CreateUserDto): Promise<UserDocument> {
        if (!userDto.email) {
            throw new BadRequestException('Please Provide a valid email')
        }

        const existingUser = await this.userModel.findOne({ email: userDto.email })
        if (existingUser) {
            throw new ConflictException("The user already exist with same email.")
        }

        // Generate email verification token
        const token = randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        const newUser = new this.userModel({
            ...userDto,
            emailVerified: false,
            emailVerificationToken: token,
            emailVerificationExpires: expires,
        })
        return await newUser.save()
    }

    async findByEmail(email: string): Promise<UserDocument> {
        return await this.userModel.findOne({ email }).exec()
    }

    async findById(id: string): Promise<UserDocument> {
        const userExist = await this.userModel.findById(id).exec()
        if (!userExist) {
            throw new NotFoundException("The user not found")
        }
        return userExist
    }

    async findAll(): Promise<User[]> {
        return await this.userModel.find().exec()
    }

    async remove(id: string): Promise<void> {
        const result = await this.userModel.findByIdAndDelete(id)
        if (!result) {
            throw new BadRequestException('user not found')
        }
    }

    async validatePassword(user: UserDocument, password: string): Promise<boolean> {
        return bcrypt.compare(password, user.password)
    }

    async validateRefreshToken(userId: string, refreshToken: string): Promise<boolean> {
        const user = await this.userModel.findById(userId)
        if (!user.refreshToken) return false;
        return bcrypt.compare(refreshToken, user.refreshToken)
    }

    async updateRefreshToken(userId: string, refreshToken: string | null): Promise<void> {
        const hashedToken = refreshToken ? await bcrypt.hash(refreshToken, 12) : null;
        await this.userModel.findByIdAndUpdate(userId, { refreshToken: hashedToken });
      }

    async incrementLoginAttempts(user: UserDocument): Promise<void> {
        const MAX_ATTEMPTS = 5;
        const LOCK_TIME = 15 * 60 * 1000; // 15 minutes
        let updates: any = { $inc: { loginAttempts: 1 } };
        // If this update causes attempts to exceed max, set lockUntil
        if ((user.loginAttempts || 0) + 1 >= MAX_ATTEMPTS) {
            updates.$set = { lockUntil: new Date(Date.now() + LOCK_TIME) };
        }
        await this.userModel.findByIdAndUpdate(user._id, updates);
    }

    async resetLoginAttempts(user: UserDocument): Promise<void> {
        await this.userModel.findByIdAndUpdate(user._id, { loginAttempts: 0, lockUntil: null });
    }

    async setPasswordResetToken(userId: string, token: string, expires: Date): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, {
            passwordResetToken: token,
            passwordResetExpires: expires,
        });
    }

    async findByResetToken(token: string): Promise<UserDocument | null> {
        return this.userModel.findOne({ passwordResetToken: token }).exec();
    }

    async updatePassword(userId: string, newPassword: string): Promise<void> {
        const hashed = await bcrypt.hash(newPassword, 12);
        await this.userModel.findByIdAndUpdate(userId, { password: hashed });
    }

    async clearPasswordResetToken(userId: string): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, {
            passwordResetToken: null,
            passwordResetExpires: null,
        });
    }

    async setEmailVerificationToken(userId: string, token: string, expires: Date): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, {
            emailVerificationToken: token,
            emailVerificationExpires: expires,
        });
    }

    async findByEmailVerificationToken(token: string): Promise<UserDocument | null> {
        return this.userModel.findOne({ emailVerificationToken: token }).exec();
    }

    async verifyEmail(userId: string): Promise<void> {
        await this.userModel.findByIdAndUpdate(userId, {
            emailVerified: true,
            emailVerificationToken: null,
            emailVerificationExpires: null,
        });
    }
    }      