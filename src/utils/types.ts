export type CreateUserType = {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
};

export type LoginUserType = {
  email: string;
  password: string;
};

export type redisTokenType = {
  token: string;
  expiryDate: any;
  user: string;
};

export type tokenType = {
  token: string;
};

export type ForgotPasswordType = {
  email: string;
};
