import { IsEmail, IsEnum, IsOptional, IsString } from "class-validator";
import { Role } from "src/common/role.enum";

export class CreateUserDto {
    @IsEmail()
    email: string;

    @IsString()
    firstName: string

    @IsString()
    lastName: string

    @IsOptional()
    @IsEnum(Role, { each: true })
    roles: Role[]
}