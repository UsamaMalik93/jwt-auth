import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import jwtConfig from "src/config/jwt.config";

@Module({
    imports: [
        ConfigModule.forFeature(jwtConfig),
    ],
    controllers: [

    ],
    providers: [],
    exports: [],
})
export class AuthModule { }
