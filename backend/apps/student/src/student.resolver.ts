import { Args, Mutation, Query, Resolver } from "@nestjs/graphql";
import { StudentCreateDto } from "./dto/create-student.input";
import { UpdateStudentDto } from "./dto/update-studnet.input";
import { Student } from "./entities/student.entity";
import { StudentService } from "./student.service";

@Resolver(() => Student)
export class StudentResolver {
    constructor(private studentService: StudentService) { }

    @Query(() => [Student], { name: "getAllStudents" })
    findAll() {
        return this.studentService.findAll();
    }

    @Query(() => [Student], { name: "getStudent" })
    findOne(@Args('id') id: string) {
        return this.studentService.findOne(id);
    }

    @Mutation(() => Student, { name: "deleteStudent" })
    delete(@Args('id') id: string) {
        return this.studentService.delete(id);;
    }

    @Mutation(() => Student, { name: "createStudent" })
    create(@Args('studentCreateDto') studentCreateDto: StudentCreateDto) {
        return this.studentService.create(studentCreateDto)
    }

    @Mutation(() => Student, { name: "updateStudent" })
    update(@Args('updateStudentDto') updateStudentDto: UpdateStudentDto) {
        return this.studentService.update(updateStudentDto.id, updateStudentDto);
    }

}