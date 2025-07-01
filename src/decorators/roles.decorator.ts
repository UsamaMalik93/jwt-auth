import { SetMetadata } from "@nestjs/common";
import { Role } from "src/common/role.enum";

export const Roles = (...roles: Role[]) => SetMetadata('roles', roles)
// This will create a @Role decorator
// Can be used like @Roles(Role.Admin)
// (...roles: Role[]): Accepts a list of allowed roles (like @Roles(Role.Admin, Role.Manager)).
// SetMetadata(key, value) is a NestJS helper used to attach custom metadata to route handlers