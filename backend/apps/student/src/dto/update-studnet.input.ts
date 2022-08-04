import { Field, InputType, Int } from "@nestjs/graphql";

@InputType()
export class UpdateStudentDto {
    @Field()
    id: string
    @Field()
    name: string;
    @Field()
    gender: string;
    @Field()
    address: string;
    @Field()
    mobileNo: string;
    @Field(type => Date)
    dateOfBirth: Date;
    @Field()
    inEdit: boolean;
    @Field(type => Int)
    age: number;
    @Field()
    isArchive: boolean;


}