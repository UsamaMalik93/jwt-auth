import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { Role } from "src/common/role.enum";
@Schema({ timestamps: true })
export class User {
    @Prop({ require: true, unique: true })
    email: string;

    @Prop({ required: true, type: String })
    firstName: string;

    @Prop({ required: true, type: String })
    lastName: string

    @Prop({ required: true, type: String, unique: true })
    password: string;

    @Prop({ required: true, enum: Role, default: [Role.USER], type: [String] })
    role: Role[]

    @Prop({ required: true, type: String })
    refreshToken: string;

    @Prop({ required: false, type: Boolean })
    isActive: boolean;

    @Prop({ required: false, type: Number, default: 0 })
    loginAttempts: number;

    @Prop({ required: false, type: Date })
    lockUntil: Date;

    @Prop({ required: false, type: String })
    passwordResetToken: string;

    @Prop({ required: false, type: Date })
    passwordResetExpires: Date;

    @Prop({ required: false, type: Boolean, default: false })
    emailVerified: boolean;

    @Prop({ required: false, type: String })
    emailVerificationToken: string;

    @Prop({ required: false, type: Date })
    emailVerificationExpires: Date;
}

export type UserDocument = HydratedDocument<User>;
export const userSchema = SchemaFactory.createForClass(User);