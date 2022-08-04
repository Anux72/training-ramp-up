import { ObjectType, Field } from '@nestjs/graphql';
import {
  Column,
  DeleteDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';

@ObjectType()
@Entity()
export class Student {
  @Field()
  @PrimaryGeneratedColumn('uuid')
  id: String;

  @Field()
  @Column()
  studentName: string;

  @Field()
  @Column()
  gender: string;

  @Field()
  @Column()
  address: string;

  @Field()
  @Column()
  phone: string;

  @Field()
  @Column()
  dob: string;

  @Field({ nullable: true })
  @DeleteDateColumn()
  deletedAt: Date;
}
