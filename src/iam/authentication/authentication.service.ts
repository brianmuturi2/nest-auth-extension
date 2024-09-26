import { ConflictException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up/sign-up.dto';
import { SignInDto } from './dto/sign-in/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import jwtConfig from '../config/jwt.config';
import { ConfigType } from '@nestjs/config';

@Injectable()
export class AuthenticationService {
    constructor(
        @InjectRepository(User) private readonly usersRepository: Repository<User>,
        private readonly hashingService: HashingService,
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>
    ){}

    async signUp(SignUpDto: SignUpDto) {
        try {
            const user = new User();
            user.email = SignUpDto.email;
            user.password = await this.hashingService.hash(SignUpDto.password);
    
            await this.usersRepository.save(user);
        } catch (error) {
            const pgUniqueViolationErrorCode = '23505';
            if (error.code === pgUniqueViolationErrorCode) {
                throw new ConflictException();
            }
            throw error;
        }

    }

    async signIn(signInDto: SignInDto) {
        const user = await this.usersRepository.findOneBy({
            email: signInDto.email
        });

        if (!user) {
            throw new UnauthorizedException('User does not exist');
        }
        const isEqual = await this.hashingService.compare(
            signInDto.password,
            user.password
        );
        if (!isEqual) {
            throw new UnauthorizedException('Password does not match');
        }
        const accessToken = await this.jwtService.signAsync(
            {
                sub: user.id,
                email: user.email,
            },
            {
                audience: this.jwtConfiguration.audience,
                issuer: this.jwtConfiguration.issuer,
                secret: this.jwtConfiguration.secret,
                expiresIn: this.jwtConfiguration.accessTokenTtl
            }
        );
        return {accessToken};
    }
}
