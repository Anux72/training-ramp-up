import { Field, Int, ObjectType } from "@nestjs/graphql";
import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@ObjectType()
@Entity()
export class Student {
    // type definitions
    @Field()
    @PrimaryGeneratedColumn('uuid')
    id: string;

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

    @Field(type => Date)
    @Column()
    dateOfBirth: Date;

    @Field()
    @Column()
    inEdit: boolean;

    @Field(type => Int)
    @Column()
    age: number;

}