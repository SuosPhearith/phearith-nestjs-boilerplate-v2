import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';
import { JwtService } from 'src/auth/jwt.service';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      // Get request and response objects
      const request = context.switchToHttp().getRequest();
      const response = context.switchToHttp().getResponse();

      // Get cookies
      const { accessToken, refreshToken } = request.cookies;
      if (!accessToken && !refreshToken) return false;

      // Verify the access token
      let decodedToken: any;
      try {
        decodedToken = await this.jwtService.verify(accessToken);
      } catch (error) {
        // If access token is expired, refresh the tokens
        if (refreshToken) {
          try {
            const tokens = await this.authService.refreshToken(refreshToken);
            response.cookie('accessToken', tokens.accessToken, {
              httpOnly: true,
              secure: true,
            });
            response.cookie('refreshToken', tokens.refreshToken, {
              httpOnly: true,
              secure: true,
            });
            decodedToken = await this.jwtService.verify(tokens.accessToken);
          } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
          }
        } else {
          throw new UnauthorizedException('Invalid access token');
        }
      }

      const userId = decodedToken.id;
      const sessionVersion = decodedToken.session;
      const sessionToken = decodedToken.sessionToken;

      // Fetch the user from the database
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      // Check if the user exists and is valid
      if (!user || !user.status) return false;

      // Check if the session version is valid
      if (!sessionVersion || sessionVersion !== user.session) return false;

      // Check if the session token is valid
      const isSessionToken = await this.prisma.userSession.findUnique({
        where: { sessionToken },
      });
      if (!isSessionToken) return false;

      // Remove password field
      delete user.password;
      request.user = user;
      request.session = sessionToken;
      return true;
    } catch (error) {
      return false;
    }
  }
}
