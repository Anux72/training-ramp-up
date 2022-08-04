import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { StudentModule } from './student.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(StudentModule);
  app.enableCors();
  await app.listen(5000);
}
bootstrap();
