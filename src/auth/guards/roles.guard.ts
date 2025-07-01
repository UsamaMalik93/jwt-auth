import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Role } from "src/common/role.enum";
@Injectable()
export class RoleGuards implements CanActivate {
    constructor(private reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {

        // This lets you apply roles either at method level or class level.
        const requiredRoles = this.reflector.getAllAndOverride<Role[]>('roles', [
            context.getHandler(),
            context.getClass()
        ])

        // If no @Roles(...) is used, allow the request by default.
        if (!requiredRoles) return true

        // Gets the current logged-in user (set by an auth guard like JwtAuthGuard).
        const { user } = context.switchToHttp().getRequest()

        // Check If User Has Required Role(s)
        return requiredRoles.some((role) => user.roles.includes(role))
    }
}

// Interface that all guards must implement. The canActivate method decides if a route can be accessed.
// ExecutionContext: Provides context about the current request.
// Reflector: Used to read metadata (like roles) that you set using @Roles(...).

// it will be used like this on controller @UseGuards(JwtAuthGuard, RolesGuard)
