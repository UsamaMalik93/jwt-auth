import { Body, Controller, Delete, Get, Param, Post } from "@nestjs/common";
import { UserService } from "./use.service";
import { CreateUserDto } from "./dto/create-user.dto";

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
    //GUARDS HERE
    //ROLES
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