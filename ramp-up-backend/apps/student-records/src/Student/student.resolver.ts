
import { Resolver,Query, Mutation, Args, Int } from '@nestjs/graphql';
import { AddStudentDTO } from './dto/addStudent.input';
import { UpdateStudentDTO } from './dto/updateStudent.input';
import { Student } from './entities/student.entity';
import { StudentService } from './student.service';

@Resolver('Student')
export class StudentResolver {

    constructor(private studentService: StudentService){}
    @Query(()=> [Student], {name: "getAllStudents"})        
    async findAll(){
        try {
            const finds = await this.studentService.findAll();
            console.log(finds)
             return finds;
        } catch (error) {
            console.log(error)
        }
       
    } 

    @Mutation(()=> Student,{name: "addStudent"})
    async addStudent(@Args('student') student: AddStudentDTO){
        return await this.studentService.addStudent(student)
    }
    @Mutation(() => Student)
    async updateStudent(@Args('student') student: UpdateStudentDTO){
        return await this.studentService.updateStudent(student.id,student)
    }
    @Mutation(() => Student)
    async removeStudent(@Args('id') id:string ){        
        return await this.studentService.removeStudent(id)
    }
}
