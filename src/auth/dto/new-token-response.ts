import { Field, ObjectType } from "@nestjs/graphql"

@ObjectType()
export class NewTokenResponse {
    @Field()
    accessToken: String
    
    @Field()
    refreshToken: String
}