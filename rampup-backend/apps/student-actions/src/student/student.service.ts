import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateStudentInput } from './dto/create-student.input';
import { UpdateStudentInput } from './dto/update-student.input';
import { Student } from './entities/student.entity';

@Injectable()
export class StudentService {
  constructor(
    @InjectRepository(Student) private studentRepository: Repository<Student>,
  ) {}

  async create(createStudentInput: CreateStudentInput): Promise<Student> {
    let stud = this.studentRepository.create(createStudentInput);
    return await this.studentRepository.save(stud);
  }

  async findAll(): Promise<Student[]> {
    return await this.studentRepository.find();
  }

  async findOne(id: string): Promise<Student> {
    return await this.studentRepository.findOneBy({ id });
  }

  async update(id: string, updateStudentInput: UpdateStudentInput) {
    let stud: Student = this.studentRepository.create(updateStudentInput);
    stud.id = id;
    return await this.studentRepository.save(stud);
  }

  async remove(id: string) {
    const res = await this.studentRepository.softDelete(id);
    if (!res.affected) {
      throw new NotFoundException(`No record with id ${id}`);
    }
    return res;
  }
}
