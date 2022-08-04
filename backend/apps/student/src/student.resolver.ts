import { Query, Resolver } from "@nestjs/graphql";
import { Student } from "./entities/student.entity";

@Resolver(() => Student)
export class StudentResolver {

    @Query(() => Student)
    findAll() {
        return 'Hello student!';
    }
}