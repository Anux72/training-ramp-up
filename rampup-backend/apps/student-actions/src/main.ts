import { NestFactory } from '@nestjs/core';
import { StudentActionsModule } from './student-actions.module';

async function bootstrap() {
  const app = await NestFactory.create(StudentActionsModule);
  await app.listen(3000);
}
bootstrap();
