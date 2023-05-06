import { HttpException, HttpStatus, Injectable, Inject } from '@nestjs/common';
import { User } from './user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  CreateUserType,
  ForgotPasswordType,
  LoginUserType,
  tokenType,
} from 'src/utils/types';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ChangePasswordDto, ForgotPasswordDto } from './dto/user.dto';
// FOr mailing
import { MailerService } from '@nestjs-modules/mailer';
import { join } from 'path';
import { EmailService } from './../email/email.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) protected readonly userRepository: Repository<User>,
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly mailerService: MailerService,
    private emailService: EmailService,
  ) {}

  /**
   * This function finds a user by their email using an asynchronous operation.
   * @param {string} option - The parameter "option" is a string that represents the email of the user
   * that we want to find in the database. The function uses the email to search for a user in the
   * "userRepository" and returns the user object if found. The function is marked as async, which means
   * it returns a promise
   * @returns The `findUser` function is returning a Promise that resolves to the result of calling the
   * `findOneBy` method of the `userRepository` object with an object containing the `email` property set
   * to the `option` parameter. The result is likely a single user object that matches the specified
   * email.
   */
  async findUser(option: string) {
    return await this.userRepository.findOneBy({ email: option });
  }

  /**
   * This function verifies if a user is authorized by checking the validity of their access token.
   * @param {any} body - The `body` parameter is an object that contains the request headers, including
   * the `authorization` header which contains the access token. The function uses this access token to
   * verify the user's identity.
   * @returns The function `verifyUser` returns a boolean value. It returns `true` if the `accessToken`
   * provided in the request header is verified successfully using the `jwtService.verifyAsync` method,
   * and it returns `false` if there is an error while verifying the token.
   */
  async verifyUser(token: string) {
    try {
      await this.jwtService.verifyAsync(token);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * This function refreshes the access token by verifying the refresh token and generating a new access
   * token with a limited expiration time.
   * @param {any} request - The `request` parameter is an object that represents the HTTP request being
   * made to the server. It contains information such as the request method, headers, query parameters,
   * and request body.
   * @param {any} response - The `response` parameter is an object that represents the HTTP response that
   * will be sent back to the client. It is used to send data back to the client, such as the access
   * token in this case.
   * @returns An object with a property `token` that contains a new access token generated using the
   * user's email and id, and expires in 60 seconds. If there is an error, it throws an
   * `UnauthorizedException`.
   */
  async refresh(request: any, response: any) {
    try {
      const getRefreshToken = request.cookies['refresh_token'];
      console.log(getRefreshToken);
      const { email } = await this.jwtService.verifyAsync(getRefreshToken);
      const user = await this.findUser(email);
      const payload = { email: user.email, id: user.id };

      const accessToken = await this.jwtService.signAsync(payload, {
        expiresIn: '60s',
      });
      const refreshToken = await this.jwtService.signAsync(payload);

      response.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        // secure: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, //1 week
      });

      return {
        token: accessToken,
      };
    } catch (e) {
      throw new HttpException('User unathorized', HttpStatus.UNAUTHORIZED);
    }
  }
  /**
   * This function retrieves the logged-in user's information from the request body using their access
   * token.
   * @param {any} body - The `body` parameter is an object that contains the request body, including the
   * headers. The `headers` property of the `body` object contains the authorization header, which is
   * used to extract the access token.
   * @returns The `getLoggedinUser` function returns the user data (excluding the password) of the user
   * who is logged in, after verifying their access token and finding their email in the database. If
   * there is an error during this process, it throws an `UnauthorizedException`.
   */
  async getLoggedinUser(body: any) {
    console.log(body.headers.authorization.replace('Bearer ', ''));

    try {
      const accessToken = body.headers.authorization.replace('Bearer ', '');
      const { email } = await this.jwtService.verifyAsync(accessToken);
      const { password, ...data } = await this.findUser(email);
      return data;
    } catch (e) {
      throw new HttpException('User unathorized', HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * This is an async function that registers a user by saving their details and hashed password to a
   * repository.
   * @param {CreateUserType} body - CreateUserType, which is likely an interface or type defining the
   * shape of an object containing user details such as name, email, and password.
   * @returns This function is returning a Promise that resolves to the saved user object in the database
   * after hashing the password using bcrypt.
   */
  async registerUser(body: CreateUserType) {
    const { password, ...userDetails } = body;
    const userExists = await this.findUser(body.email);
    if (userExists) {
      throw new HttpException(
        'A user with this account exists',
        HttpStatus.BAD_REQUEST,
      );
    }
    const payload = { email: body.email };
    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '1d',
    });
    const user = this.userRepository.save({
      password: await bcrypt.hash(password, 12),
      activation_token: token,
      ...userDetails,
    });

    await this.emailService.sendUserEmail(
      body.first_name,
      body.email,
      token,
      'Activation Email',
    );
    return user;
  }

  async resendActivationEmail(email: string) {
    try {
      const user = await this.findUser(email);
      // console.log(user.isActive, 'Active');
      if (user.isActive) {
        throw new HttpException(
          'Request rejected, User is active',
          HttpStatus.UNAUTHORIZED,
        );
      }
      const payload = {
        email: email,
        id: user.id,
      };
      const token = await this.jwtService.signAsync(payload, {
        expiresIn: '1d',
      });
      await this.userRepository.update(user.id, {
        activation_token: token,
      });
      await this.emailService.sendUserEmail(
        user.first_name,
        user.email,
        token,
        'Activation Email',
      );

      return true;
    } catch (err) {
      throw new HttpException(
        'This user is active already or not found, Email was not sent',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  /**
   * This function confirms a user's email by verifying their activation token and updating their account
   * status to active.
   * @param {tokenType} body - The parameter `body` is of type `tokenType`, which is likely a custom type
   * defined elsewhere in the codebase. It is used to pass in a token for email confirmation.
   * @returns An object containing an access token and a refresh token is being returned.
   */
  async confirmEmail(body: tokenType) {
    const user = await this.userRepository.findOneBy({
      activation_token: body.token,
    });
    if (!user) {
      throw new HttpException(
        'Wrong or expired activation token',
        HttpStatus.BAD_GATEWAY,
      );
    }

    const decodedEmail = await this.jwtService.verifyAsync(body.token);

    try {
      const user = await this.findUser(decodedEmail?.email);
      if (user.isActive) {
        throw new HttpException(
          'User is already active',
          HttpStatus.EXPECTATION_FAILED,
        );
      }
      await this.userRepository.update(user.id, {
        isActive: true,
        activation_token: '',
      });
      const payload = { email: user.email, id: user.id };
      const token = await this.jwtService.signAsync(payload, {
        expiresIn: '60s',
      });
      const refreshToken = await this.jwtService.signAsync(payload, {
        expiresIn: '60s',
      });

      return { accessToken: token, refreshToken: refreshToken };
    } catch (error) {
      console.log(error);
      throw new HttpException(
        'Wrong or expired link, Email not activated',
        HttpStatus.BAD_GATEWAY,
      );
    }
  }

  //LOGIN LOGIC
  async login(body: LoginUserType) {
    /* This code block is defining a method called `login` in the `UserService` class. This method takes in
a `LoginUserType` object as an argument, which contains an email and password. */

    const user = await this.findUser(body.email);
    if (!user) {
      throw new HttpException(
        'Wrong username or password',
        HttpStatus.FORBIDDEN,
      );
    }

    /* This code block is comparing the password provided by the user during login with the hashed password
    stored in the database for the corresponding user. It uses the `bcrypt` library to compare the
    passwords. If the passwords do not match, it throws an `HttpException` with a `FORBIDDEN` status
    code, indicating that the login attempt was unsuccessful due to incorrect username or password. */
    const compare = await bcrypt.compare(body.password, user.password);
    if (!compare) {
      throw new HttpException(
        'Wrong username or password',
        HttpStatus.FORBIDDEN,
      );
    }

    /* This code block is generating a JSON Web Token (JWT) for the authenticated user. It creates a
    payload object containing the user's email and id, and then uses the `jwtService` to sign the
    payload with a secret key and an expiration time of 30 seconds to generate an access token. It also
    generates a refresh token without an expiration time. Finally, it returns an object containing both
    the access token and the refresh token. The access token can be used to authenticate the user for a
    limited time period, while the refresh token can be used to generate a new access token when the
    previous one expires. */
    const payload = { email: user.email, id: user.id };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '60s',
    });
    const refreshToken = await this.jwtService.signAsync(payload);

    return {
      token: accessToken,
      refreshToken: refreshToken,
    };
  }

  /**
   * This function logs out a user by blacklisting their refresh token and clearing the cookie.
   * @param {any} response - The `response` parameter is an object that represents the HTTP response that
   * will be sent back to the client. It is used to set headers, cookies, and the response body.
   * @param {any} request - The `request` parameter is an object that contains information about the
   * incoming HTTP request, such as the headers, query parameters, and cookies. It is used in this
   * function to retrieve the refresh token from the cookies.
   * @returns a boolean value of `true` if the logout process is successful. If there is an error, it
   * will throw an `HttpException` with a message of 'Invalid Token' and a status code of
   * `HttpStatus.BAD_REQUEST`.
   */
  async logout(response: any, request: any) {
    try {
      const getRefreshToken = request.cookies['refresh_token'];
      const decodedRefreshToken = await this.jwtService.decode(getRefreshToken);
      const expiry = decodedRefreshToken['exp'];

      //check for difference in today and token expiration date in seconds
      const expiryDate: any = new Date(expiry * 1000);
      const today: any = new Date();
      const dateDifferenceInSeconds: number =
        Math.abs(expiryDate - today) / 1000;
      // console.log(dateDifferenceInSeconds, 'seconds');
      //write data to redis to blacklist
      await this.cacheManager.set(
        getRefreshToken,
        getRefreshToken,
        dateDifferenceInSeconds,
      );
      //clear the token
      response.clearCookie('refresh_token');
      return true;
    } catch (e) {
      throw new HttpException('Invalid Token', HttpStatus.BAD_REQUEST);
    }
  }

  /* The above code is implementing a forgot password functionality for a user. It first finds the user
by their email address using a repository, then generates a JWT token with a 5-minute expiration
time and updates the user's reset_token and reset_count fields in the database. It then sends an
email to the user with the token and a message indicating that it is a password reset email. If the
user is not found, it does not throw an exception to avoid revealing whether or not the email
address exists in the system. If there is an error during the process, it logs the error and returns
true. */
  async forgotPassword(body: ForgotPasswordDto) {
    try {
      const user = await this.userRepository.findOneBy({ email: body.email });
      const payload = { email: user.email, id: user.id };
      //we are not going to throw an exeption
      //for user not found this way user emails are not guessed
      if (user) {
        const token = await this.jwtService.signAsync(payload, {
          expiresIn: '300s',
        });

        //write token to user db and update the reset count
        this.userRepository.update(user.id, {
          reset_token: token,
          reset_count: user.reset_count + 1,
        });
        const emailType = 'Reset Password';
        // send the mail
        await this.emailService.sendUserEmail(
          user.first_name,
          user.email,
          token,
          emailType,
        );
      }
    } catch (error) {
      console.log(error);
      return true;
    }

    return true;
  }

  /**
   * This function changes a user's password and returns a new access token and refresh token.
   * @param {ChangePasswordDto} body - The request body containing the data needed to change the user's
   * password. It includes the current access token, the new password, and the confirmation of the new
   * password.
   * @param {string} headerToken - The `headerToken` parameter is a string that represents the JWT
   * token that is included in the authorization header of the HTTP request. It is used to authenticate
   * the user and authorize the password change operation.
   * @returns An object containing a new access token and a refresh token is being returned.
   */
  async change_password(body: ChangePasswordDto, headerToken: string) {
    const { token, password, confirm_password } = body;
    // const headerToken = body.headers.authorization.replace('Bearer ', '');

    const accessToken = token ? token : headerToken;
    console.log(accessToken, 'Access');

    try {
      if (accessToken && (await this.jwtService.verifyAsync(accessToken))) {
        const { email } = await this.jwtService.verifyAsync(accessToken);
        const user = await this.userRepository.findOneByOrFail({
          email,
        });
        if (password === confirm_password) {
          await this.userRepository.update(user.id, {
            password: await bcrypt.hash(password, 12),
          });
        }
        const payload = { email: user.email, id: user.id };
        const newaccessToken = await this.jwtService.signAsync(payload, {
          expiresIn: '300s',
        });
        const refreshToken = await this.jwtService.signAsync(payload);
        await this.userRepository.update(user.id, {
          reset_token: '',
        });
        return {
          token: newaccessToken,
          refreshToken: refreshToken,
        };
      }
    } catch (error) {
      console.log(error);
      throw new HttpException('User not updated', HttpStatus.BAD_REQUEST);
    }
  }
}
