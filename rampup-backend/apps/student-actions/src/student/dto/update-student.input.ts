import { CreateStudentInput } from './create-student.input';
import { InputType, Field, Int, PartialType } from '@nestjs/graphql';

@InputType()
export class UpdateStudentInput extends PartialType(CreateStudentInput) {
  @Field()
  id: string;

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
