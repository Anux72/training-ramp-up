import { Injectable, } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { StudentCreateDto } from "./dto/create-student.input";
import { UpdateStudentDto } from "./dto/update-studnet.input";
import { Student } from "./entities/student.entity";

@Injectable()
export class StudentService {
    constructor(@InjectRepository(Student) private studentRepository: Repository<Student>) { }

    async findAll(): Promise<Student[]> {
        return await this.studentRepository.find({
            where: {
                isArchive: false
            }
        })

    }

    async findOne(id: string): Promise<Student[]> {
        return await this.studentRepository.find({
            where: {
                id,
                isArchive: false
            },
        })
    }

    async create(student: StudentCreateDto): Promise<Student> {
        let studentDetial: Student = this.studentRepository.create(student);
        return await this.studentRepository.save(studentDetial);
    }

    async delete(id: string): Promise<Student> {
        let existingStudnet: Student = await this.studentRepository.findOneBy({ id });
        existingStudnet.isArchive = true
        return this.studentRepository.save(existingStudnet);
    }

    async update(id: string, student: UpdateStudentDto): Promise<Student | string> {
        let newStudent: Student = this.studentRepository.create(student);
        newStudent.id = id;
        return this.studentRepository.save(newStudent)

    }


}