import { Injectable } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { Student } from '../entity/student.entity';
import { StudentDto } from '../dto/student.dto';

@Injectable()
export class StudentsService {
  constructor(private dataSource: DataSource) {}

  async getStudents(): Promise<any> {
    try {
      return await this.dataSource.manager.find(Student);
    } catch (e) {
      return Error('Error getting students');
    }
  }

  async addStudent(newStudent: StudentDto): Promise<any> {
    try {
      await this.dataSource.manager.save(Student, newStudent);
      return `Student added to database`;
    } catch (e) {
      return Error('Error adding student');
    }
  }

  async updateStudent(id: string, newStudent: StudentDto): Promise<any> {
    try {
      await this.dataSource.manager.update(
        Student,
        { id: parseInt(id) },
        newStudent,
      );
      return `Student with the id ${id} has been updated`;
    } catch (e) {
      return Error('Error updating student');
    }
  }

  async deleteStudent(id: string): Promise<any> {
    try {
      await this.dataSource.manager.delete(Student, { id: parseInt(id) });
      return `Student with the id ${id} has been deleted`;
    } catch (e) {
      return Error('Error deleting student');
    }
  }
}
