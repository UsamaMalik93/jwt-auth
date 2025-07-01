import { BadRequestException, ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, UserDocument } from "./user.model";
import { Model } from "mongoose";
import * as bcrypt from 'bcryptjs'
import { RegisterDto } from "src/auth/dto/register.dto";
import { CreateUserDto } from "./dto/create-user.dto";

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

        const existingUser = this.userModel.findOne({ email: userDto.email })
        if (existingUser) {
            throw new ConflictException("The user already exist with same email.")
        }

        const newUser = new this.userModel(userDto)
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
    }      