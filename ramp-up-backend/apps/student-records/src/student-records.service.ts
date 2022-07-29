import { Injectable } from '@nestjs/common';

@Injectable()
export class StudentRecordsService {
  getHello(): string {
    return 'Hello World!';
  }
}
