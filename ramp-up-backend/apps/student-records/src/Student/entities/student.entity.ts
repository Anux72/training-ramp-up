import { Field, Int, ObjectType } from '@nestjs/graphql';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@ObjectType()
@Entity()
export class Student {
  @Field()
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Field()
  @Column()
  Student_id: number;

  @Field()
  @Column()
  name: string;

  @Field()
  @Column()
  gender: string;

  @Field()
  @Column()
  address: string;

  @Field()
  @Column()
  mobileNo: string;

  @Field()
  @Column()
  DOB: string;

  @Field()
  @Column()
  age: number;

  @Field()
  @Column()
  isArchive: boolean;
}
