import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Role } from "src/common/role.enum";

export type UserDocument=User & Document
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

    @Prop({ required: true, enum: Role, default: [Role.USER] })
    role: Role[]

    @Prop()
    refreshToken:string
}

export const userSchema = SchemaFactory.createForClass(User)