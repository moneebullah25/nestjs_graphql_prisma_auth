import { Field, ObjectType } from "@nestjs/graphql";
import { IsBoolean, IsNotEmpty } from "class-validator";

@ObjectType()
export class LogoutResponse {
    @Field()
    @IsNotEmpty()
    @IsBoolean()
    loggedOut: boolean;
}