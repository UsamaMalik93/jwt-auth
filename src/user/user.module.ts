import { Module } from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { User, userSchema } from "./user.model";
import { UsersController } from "./user.controller";
import { UserService } from "./use.service";

@Module({
    imports: [MongooseModule.forFeature([
        { name: User.name, schema: userSchema }]
    )],
    controllers: [UsersController],
    providers: [UserService],
    exports: [UserService]
})
export class UsersModule { }