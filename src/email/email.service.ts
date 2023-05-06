import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { join } from 'path';
import { template } from 'handlebars';
@Injectable()
export class EmailService {
  constructor(private mailerService: MailerService) {}

  async sendUserEmail(name: string, email: string, token: string, emailType) {
    let url;
    let templateName;
    let emailTitle;

    switch (emailType) {
      case 'Reset Password':
        url = process.env.FORGOT_PASSWORD_URL + token;
        templateName = 'forgot';
        emailTitle = 'Reset Password';
        break;
      case 'Activation Email':
        url = process.env.ACTIVATE_EMAIL_URL + token;
        templateName = 'activation';
        emailTitle = 'Confirm Your Email';
        break;
    }

    try {
      await this.mailerService.sendMail({
        to: email,
        // from: '"Support Team" <support@example.com>', // override default from
        subject: emailTitle,
        template: join(__dirname, `../mail/templates/${templateName}`),
        context: {
          // filling <%= %> brackets with content
          emailTitle: emailTitle,
          name: name,
          url,
          app_name: process.env.APP_NAME,
        },
      });
    } catch (error) {
      console.log(error);
      throw new HttpException(
        'Something went wrong, email could not be sent',
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
