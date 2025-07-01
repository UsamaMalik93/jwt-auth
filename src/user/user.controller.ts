import { Body, Controller, Delete, Get, Param, Post, UseGuards } from "@nestjs/common";
import { UserService } from "./use.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { JwtAuthGuard } from "src/auth/guards/role-auth.guard";
import { RoleGuards } from "src/auth/guards/roles.guard";
import { Roles } from "src/decorators/roles.decorator";
import { Role } from "src/common/role.enum";

@Controller('users')

export class UsersController{
    constructor(private readonly userService:UserService){}

    @Post()
    //GUARDS HERE
    //ROLES
    create(@Body() createUserDto:CreateUserDto){
        return this.userService.create(createUserDto)
    }

    @Get()
    @UseGuards(JwtAuthGuard, RoleGuards)
    @Roles(Role.ADMIN)
    findAll(){
        return this.userService.findAll()
    }

    @Get(':id')
    findOne(@Param('id') id:string){
        return this.userService.findById(id)
    }

    @Delete(':id')
    remove(@Param("id") id:string){
        return this.userService.remove(id)
    }
}