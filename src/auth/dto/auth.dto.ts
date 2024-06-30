import { IsEmail, IsString, MinLength } from 'class-validator'

export class AuthDto {
	//@IsOptional() - опциаональный
	@IsEmail()
	email: string
	@MinLength(6, {
		message: 'Пароль должен быть длиннее 6 символов.'
	})
	@IsString()
	password: string
}
