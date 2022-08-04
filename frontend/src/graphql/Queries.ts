import { gql } from '@apollo/client';

export const GET_ALL_STUDENTS_QUERY = gql`
  query getAllStudents {
    getAllStudents {
      id
      name
      gender
      address
      dateOfBirth
      mobileNo
      age
      inEdit
      isArchive
    }
  }
`;

export const CREATE_STUDENT_QUERY = gql`
  mutation createStudent(
    $name: String!, 
    $gender: String!, 
    $address: String!, 
    $dateOfBirth: DateTime!, 
    $mobileNo: String!, 
    $age: Int!, 
    $inEdit: Boolean!, 
    $isArchive: Boolean!
    ) {
    createStudent(
      studentCreateDto:{
        name: $name, 
        gender: $gender, 
        address: $address, 
        dateOfBirth: $dateOfBirth, 
        mobileNo: $mobileNo, 
        age: $age, 
        inEdit: $inEdit, 
        isArchive: $isArchive
      }     
      ) {
      name
      gender
      address
      dateOfBirth
      mobileNo
      age
      inEdit
      isArchive
    }
  }
`;

export const DELETE_STUDENT_QUERY = gql`
mutation deleteStudent($id: String!) {
  deleteStudent(id: $id) {
    id
    name
  }
}
`;

export const UPDATE_STUDENT_QUERY = gql`
mutation updateStudent(
    $id:String!
    $name: String!, 
    $gender: String!, 
    $address: String!, 
    $dateOfBirth: DateTime!, 
    $mobileNo: String!, 
    $age: Int!, 
    $inEdit: Boolean!, 
    $isArchive: Boolean!
 ){
  updateStudent(
    updateStudentDto:{
        id: $id
        name: $name, 
        gender: $gender, 
        address: $address, 
        dateOfBirth: $dateOfBirth, 
        mobileNo: $mobileNo, 
        age: $age, 
        inEdit: $inEdit, 
        isArchive: $isArchive
      }     
      ) {
      id
      name
      gender
      address
      dateOfBirth
      mobileNo
      age
      inEdit
      isArchive
    }
  }
`;