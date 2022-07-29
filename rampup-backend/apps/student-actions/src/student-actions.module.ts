import { Module } from '@nestjs/common';
import { StudentActionsController } from './student-actions.controller';
import { StudentActionsService } from './student-actions.service';

@Module({
  imports: [],
  controllers: [StudentActionsController],
  providers: [StudentActionsService],
})
export class StudentActionsModule {}
