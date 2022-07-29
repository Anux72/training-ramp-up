import { Injectable, Type } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AddStudentDTO } from './dto/addStudent.input';
import { UpdateStudentDTO } from './dto/updateStudent.input';
import { Student } from './entities/student.entity';

@Injectable()
export class StudentService {
  constructor(
    @InjectRepository(Student) private studentRepository: Repository<Student>,
  ) {}

  async findAll(): Promise<Student[]> {
    return this.studentRepository.find();
  }

  async addStudent(student: AddStudentDTO): Promise<Student> {
    let std = this.studentRepository.create(student);
    return this.studentRepository.save(std);
  }

  async findOne(id: string ): Promise<Student> {
    return this.studentRepository.findOneBy({id});
  }

  async updateStudent(id: string, student: UpdateStudentDTO): Promise<Student> {
    let std: Student = this.studentRepository.create(student);
    std.id = id;
    return this.studentRepository.save(std);
  }
  async removeStudent(id: string ) {
        const std =await this.findOne(id);
        std.isArchive = true;
      return this.studentRepository.save(std); 
  }
}
