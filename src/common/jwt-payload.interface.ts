export type JwtPayload = {
    iat?: number;
    exp?: number;
    _id: string;
    email: string;
    roles: string[];
  };