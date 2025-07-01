import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { User } from "src/user/user.model";

export const getProfile = createParamDecorator(
    (_: unknown, ctx: ExecutionContext): User => {
        const request = ctx.switchToHttp().getRequest()
        return request.user
    })