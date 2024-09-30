import { Body, Controller, HttpCode, HttpStatus, Post, Res } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignUpDto } from './dto/sign-up/sign-up.dto';
import { SignInDto } from './dto/sign-in/sign-in.dto';
import { Response } from 'express';
import { Auth } from './decorators/auth.decorator';
import { AuthType } from './enums/auth-type.enum';
import { RefreshTokenDto } from './dto/sign-in/refresh-token.dto';
import { ActiveUser } from '../decorators/active-user.decorator';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { OtpAuthenticationService } from './otp-authentication.service';
import { toFileStream } from 'qrcode';

@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
    constructor(
        private authenticationService: AuthenticationService,
        private readonly otpAuthenticationService: OtpAuthenticationService
    ) {}

    @Post('sign-up')
    signUp(@Body() SignUpDto: SignUpDto) {
        return this.authenticationService.signUp(SignUpDto);
    }

    @HttpCode(HttpStatus.OK)
    @Post('sign-in')
    async signIn(
        @Res({passthrough: true}) response: Response,
        @Body() signInDto: SignInDto
    ) {
        return this.authenticationService.signIn(signInDto);
        const accessToken = await this.authenticationService.signIn(signInDto);
        response.cookie('accessToken', accessToken, {
            secure: true,
            httpOnly: true,
            sameSite: true
        })
    }

    @HttpCode(HttpStatus.OK)
    @Post('refresh-token')
    async refreshToken(
        @Res({passthrough: true}) response: Response,
        @Body() refreshTokenDto: RefreshTokenDto
    ) {
        return this.authenticationService.refreshToken(refreshTokenDto);
    }

    @Auth(AuthType.Bearer)
    @HttpCode(HttpStatus.OK)
    @Post('2fa/generate')
    async generateQrCode(
        @ActiveUser() activeUser: ActiveUserData,
        @Res() response: Response
    ) {
        const {secret, uri} = await this.otpAuthenticationService.generateSecret(
            activeUser.email
        );
        await this.otpAuthenticationService.enableTfaForUser(activeUser.email, secret);
        response.type('png');
        return toFileStream(response, uri); 
    }
}
