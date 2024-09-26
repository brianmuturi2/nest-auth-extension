import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up/sign-up.dto';
import { SignInDto } from './dto/sign-in/sign-in.dto';

@Injectable()
export class AuthenticationService {
    constructor(
        @InjectRepository(User) private readonly usersRepository: Repository<User>,
        private readonly hashingService: HashingService
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
        // TODO: We'll fill this gap in the next lesson
        return true;
    }
}
