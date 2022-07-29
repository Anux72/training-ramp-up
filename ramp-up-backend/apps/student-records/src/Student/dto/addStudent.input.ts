import { Field, InputType, Int } from '@nestjs/graphql';

@InputType()
export class AddStudentDTO {
 
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

  @Field(()=> Int)
  age: number;

   @Field()
  isArchive: boolean;
}
