import {
  Controller,
  Post,
  Get,
  Body,
  HttpException,
  HttpStatus,
  Res,
  Req,
} from '@nestjs/common';
import { Request, Response } from 'express';

import {
  CreateUserDto,
  ForgotPasswordDto,
  LoginUserDto,
  ChangePasswordDto,
} from './dto/user.dto';
import { UserService } from './user.service';
import { tokenType } from 'src/utils/types';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  /* This code is defining a `getLoggedinUser` method in the `UserController` class that handles a GET
request to the `/user` endpoint. It receives a `Request` object as a parameter and calls the
`getLoggedinUser` method of the `UserService` class passing the `Request` object as a parameter and
awaits for the response. Finally, it returns the response. This code is used to retrieve the details
of the currently logged in user. */
  @Get('')
  async getLoggedinUser(@Req() request: Request) {
    return await this.userService.getLoggedinUser(request);
  }

  /* This code is defining a `refresh` method in the `UserController` class that receives a `Request`
object and a `Response` object as parameters. It sets the status of the `Response` object to 200 and
then calls the `refresh` method of the `UserService` class passing the `Request` and `Response`
objects as parameters and awaits for the response. Finally, it returns the response. This code is
used to handle the refresh token functionality of the application. */
  @Post('refresh')
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    //we will need to blacklist the previous refresh token in the services
    //new refresh tokens are always generated
    //https://supertokens.com/blog/revoking-access-with-a-jwt-blacklist
    response.status(200);
    return await this.userService.refresh(request, response);
  }
  /* This code is defining a `register` method in the `UserController` class that receives a
`CreateUserDto` object in the request body as a parameter. It then checks if the `password` and
`confirm_password` properties of the `CreateUserDto` object match, and if they don't, it throws an
`HttpException` with a `BAD_REQUEST` status code and a message indicating that the passwords do not
match. If the passwords match, it extracts all the properties of the `CreateUserDto` object except
for the `confirm_password` property into a new object called `userDetails`. Finally, it calls the
`registerUser` method of the `UserService` class passing the `userDetails` object as a parameter and
awaits for the response. If the response is not null or undefined, it returns it. This code is used
to handle the registration functionality of the application. */
  @Post('register')
  async register(@Body() body: CreateUserDto) {
    const { confirm_password, ...userDetails } = body;
    if (body.password !== confirm_password) {
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }
    return await this.userService.registerUser(userDetails);
  }

  /* This code is defining a `login` method in the `UserController` class that receives a `LoginUserDto`
  object in the request body and a `Response` object as parameters. It then calls the `login` method
  of the `UserService` class passing the `LoginUserDto` object as a parameter and awaits for the
  response. If the response is not null or undefined, it sets a cookie named `refresh_token` in the
  `Response` object with the `refreshToken` property of the response, and returns an object with a
  `token` property containing the `token` property of the response. This code is used to handle the
  login functionality of the application. */
  @Post('login')
  async login(
    @Body() body: LoginUserDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const getResponse = await this.userService.login(body);
    if (getResponse) {
      response.cookie('refresh_token', getResponse.refreshToken, {
        httpOnly: true,
        // secure: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, //1 week
      });
    }
    response.status(200);
    return { token: getResponse.token };
  }

  @Post('logout')
  async logout(
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
  ) {
    return await this.userService.logout(response, request);
  }

  @Post('forgot_password')
  async forgotPassword(
    @Res({ passthrough: true }) response: Response,
    @Body() body: ForgotPasswordDto,
  ) {
    response.status(201);
    return await this.userService.forgotPassword(body);
  }

  @Post('change_password')
  async change_password(
    @Res({ passthrough: true }) response: Response,
    @Body() body: ChangePasswordDto,
    @Req() request: Request,
  ) {
    //works for both update and forgot password

    const headerToken =
      request.header('Authorization') &&
      request.header('Authorization').replace('Bearer ', '');

    return await this.userService.change_password(body, headerToken);
  }

  @Post('confirm_email')
  async confirmEmail(@Body() body: tokenType) {
    return await this.userService.confirmEmail(body);
  }

  @Post('resend_activation_email')
  async resendActivationEmail(@Body() body: ForgotPasswordDto) {
    return await this.userService.resendActivationEmail(body.email);
  }
}
