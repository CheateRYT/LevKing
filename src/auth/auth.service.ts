import { faker } from '@faker-js/faker'
import {
	BadRequestException,
	Injectable,
	NotFoundException,
	UnauthorizedException
} from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { User } from '@prisma/client'
import { hash, verify } from 'argon2'
import { PrismaService } from 'src/prisma.service'
import { AuthDto } from './dto/auth.dto'

@Injectable()
export class AuthService {
	constructor(
		private prisma: PrismaService,
		private jwt: JwtService
	) {}

	async login(dto: AuthDto) {
		const user = await this.validateUser(dto)
		const tokens = await this.issueTokens(user.id)
		return {
			user: this.returnUserFields(user),
			...tokens
		}
	}

	async getNewTokens(refreshToken: string) {
		const result = await this.jwt.verifyAsync(refreshToken)
		if (!result) throw new UnauthorizedException('Неправильный refresh token.')
		const user = await this.prisma.user.findUnique({
			where: {
				id: result.id
			}
		})
		const tokens = await this.issueTokens(user.id)

		return {
			user: this.returnUserFields(user),
			...tokens
		}
	}

	async register(dto: AuthDto) {
		const oldUser = await this.findUser(dto.email)

		if (oldUser) throw new BadRequestException('Пользователь уже существует')

		const user = await this.prisma.user.create({
			data: {
				email: dto.email,
				name: faker.person.firstName(),
				avatarPath: faker.image.avatar(),
				phone: faker.phone.number(),
				password: await hash(dto.password)
			}
		})

		const tokens = await this.issueTokens(user.id)

		return {
			user: this.returnUserFields(user),
			...tokens
		}
	}

	private async issueTokens(userId: string) {
		const data = { id: userId }
		const accessToken = this.jwt.sign(data, {
			expiresIn: '1h'
		})
		const refreshToken = this.jwt.sign(data, {
			expiresIn: '7d'
		})
		return { accessToken, refreshToken }
	}
	private returnUserFields(user: User) {
		return {
			id: user.id,
			email: user.email
		}
	}
	private async findUser(email: string) {
		const user = await this.prisma.user.findUnique({
			where: {
				email: email
			}
		})
		return user
	}
	private async validateUser(dto: AuthDto) {
		const user = await this.findUser(dto.email)

		if (!user) throw new NotFoundException('Пользователь не найден')

		const isValid = await verify(user.password, dto.password)
		if (!isValid) throw new UnauthorizedException('Неправильный пароль.')
		return user
	}
}
