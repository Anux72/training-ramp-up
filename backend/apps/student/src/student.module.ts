import { ApolloDriver } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { join } from 'path';
import { StudentResolver } from './student.resolver';
import { StudentService } from './student.service';
import { TypeOrmModule } from '@nestjs/typeorm'
import { Student } from './entities/student.entity';


@Module({
  imports: [GraphQLModule.forRoot({
    autoSchemaFile: join(process.cwd(), 'apps/student/src/graphql-schema.gql'),
    driver: ApolloDriver,
    cors: {
      credentials: true,
    },
  }),
  TypeOrmModule.forRoot({
    type: 'postgres',
    host: 'localhost',
    port: 5432,
    username: 'postgres',
    password: '123',
    database: 'student',
    entities: [Student],
    synchronize: true, // only use dev environment
  }),

  TypeOrmModule.forFeature([Student])
  ],
  controllers: [],
  providers: [StudentService, StudentResolver],
})
export class StudentModule { }
