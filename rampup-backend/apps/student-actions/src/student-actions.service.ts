import { Injectable } from '@nestjs/common';

@Injectable()
export class StudentActionsService {
  getHello(): string {
    return 'Hello World!';
  }
}
