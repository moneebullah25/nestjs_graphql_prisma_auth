import { Resolver, Query, Mutation, Args, Int } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { Auth } from './entities/auth.entity';
import { SignUpInput } from './dto/signup-input';
import { UpdateAuthInput } from './dto/update-auth.input';
import { SignResponse } from './dto/sign-reponse';
import { SignInInput } from './dto/signin-input';
import { LogoutResponse } from './dto/logout-response';
import { NewTokenResponse } from './dto/new-token-response';
import { CurrentUser } from './decorators/current-user.decorator';
import { CurrentUserId } from './decorators/current-user-id.decorator';
import { UseGuards } from '@nestjs/common';
import { RefreshTokenGuard } from './guards/refresh-token.guard';

@Resolver(() => Auth)
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Mutation(() => SignResponse)
  signup(@Args('signUpInput') signUpInput: SignUpInput) {
    return this.authService.signup(signUpInput);
  }

  @Mutation(() => SignResponse)
  signin(@Args('signInInput') signInInput: SignInInput) {
    return this.authService.signin(signInInput);
  }

  @Mutation(() => LogoutResponse)
  logout(@Args('id', {type: () => Int}) id: number) {
    return this.authService.logout(id);
  }

  @UseGuards(RefreshTokenGuard)
  @Mutation(() => NewTokenResponse)
  getNewTokens(
    @CurrentUserId() userId: number,
    @CurrentUser('refreshToken') refreshToken: string
  ) {
    this.authService.getNewTokens(userId, refreshToken);
  }
}
