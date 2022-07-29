import { Field, InputType, Int } from '@nestjs/graphql';

@InputType()
export class UpdateStudentDTO {
  @Field()
  id: string;
  
  @Field()  
  Student_id: number;

  @Field()
  name: string;

  @Field()
  gender: string;

  @Field()
  address: string;

  @Field()
  mobileNo: string;

  @Field()
  DOB: string;

  @Field()
  age: number;

  @Field()
  isArchive: boolean;
}
