import { Controller, Get , Post } from '@nestjs/common';
import { StudentRecordsService } from './student-records.service';

@Controller('students')
export class StudentRecordsController {
  constructor(private readonly studentRecordsService: StudentRecordsService) {}

  @Get()
  getHello(): string {
    return this.studentRecordsService.getHello();
  }

  @Post()
  addStudent():any{
    
  }
}
