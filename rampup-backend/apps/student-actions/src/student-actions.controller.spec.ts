import { Test, TestingModule } from '@nestjs/testing';
// import { StudentActionsController } from './student-actions.controller';
// import { StudentActionsService } from './student-actions.service';

describe('StudentActionsController', () => {
  // let studentActionsController: StudentActionsController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      // controllers: [StudentActionsController],
      // providers: [StudentActionsService],
    }).compile();

    // studentActionsController = app.get<StudentActionsController>(
    // StudentActionsController,
    // );
  });

  describe('root', () => {
    it('should return "Hello World!"', () => {
      // expect(studentActionsController.getHello()).toBe('Hello World!');
    });
  });
});
