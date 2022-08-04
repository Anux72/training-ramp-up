import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class CreateStudentInput {
  @Field()
  studentName: string;

  @Field()
  gender: string;

  @Field()
  address: string;

  @Field()
  phone: string;

  @Field()
  dob: string;
}
