import { Controller, Get } from '@nestjs/common';
import { StudentActionsService } from './student-actions.service';

@Controller()
export class StudentActionsController {
  constructor(private readonly studentActionsService: StudentActionsService) {}

  @Get()
  getHello(): string {
    return this.studentActionsService.getHello();
  }
}
