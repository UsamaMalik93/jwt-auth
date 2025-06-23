export interface JwtPayload {
    email: string;
    roles: string[],
    iat?: number,
    exp?: number
}