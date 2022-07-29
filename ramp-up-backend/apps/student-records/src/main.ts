import { NestFactory } from '@nestjs/core';
import { StudentRecordsModule } from './student-records.module';

async function bootstrap() {
  const app = await NestFactory.create(StudentRecordsModule);
  await app.listen(5000);
}
bootstrap();
