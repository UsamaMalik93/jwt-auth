import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { Observable } from "rxjs";
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    constructor(private reflector: Reflector) {
        super()
    }

    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const isPubic = this.reflector.getAllAndOverride<boolean>('isPublic', [
            context.getHandler(),
            context.getClass()
        ]);

        // If it is public, skip JWT authentication (return true).
        if (isPubic) return true;
        return super.canActivate(context)
    }

    // This function gets called after the JWT has been validated.
    handleRequest(err: Error, user: any) {
        if (err || !user) throw new UnauthorizedException('Invalid Token')
        return user;
    }
}

// Usage Example : @UseGuards(JwtAuthGuard, RolesGuard)
// getAllAndOverride() looks at both method-level and class-level metadata, and returns the first non-undefined value.
// super() calls the parent AuthGuard constructor. it allows to use jwt strategy.
