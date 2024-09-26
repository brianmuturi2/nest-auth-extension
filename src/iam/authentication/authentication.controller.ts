import { Body, Controller, HttpCode, HttpStatus, Post, Res } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignUpDto } from './dto/sign-up/sign-up.dto';
import { SignInDto } from './dto/sign-in/sign-in.dto';
import { Response } from 'express';
import { Auth } from './decorators/auth.decorator';
import { AuthType } from './enums/auth-type.enum';

@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
    constructor(
        private authenticationService: AuthenticationService
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
}
