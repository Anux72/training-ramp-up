import { gql } from "@apollo/client";

export const STUDENT_GET_QUERY = gql`
  query getAllStudents {
    getAllStudents {
      Student_id
      name
      id
      gender
      age
      address
      mobileNo
      DOB
      isArchive
    }
  }
`;
export const STUDENT_ADD_MUTATION = gql`
  mutation addStudent($Student_id:Float!,$name:String!,$gender: String!, $address: String!,$mobileNo:Float!,$DOB:String!,$age:Float!, $isArchive:Boolean! ) {
    addStudent(
      student: {
        Student_id: $Student_id
        name: $name
        gender:$gender
        address:$address
        mobileNo:$mobileNo
        DOB:$DOB
        age:$age
        isArchive:$isArchive
      }
    ) {
      id
      name
    }
  }
`;

export const STUDENT_UPDATE_MUTATION = gql`
  mutation updateStudent($Student_id:Float!,$name:String!,$gender: String!, $address: String!,$mobileNo:Float!,$DOB:String!,$age:Float!, $isArchive:Boolean!) {
    updateStudent(
      student: {
        id: "4188e03e-d82b-468c-875d-c601dd842e8f"
        Student_id: $Student_id
        name: $name
        gender:$gender
        address:$address
        mobileNo:$mobileNo
        DOB:$DOB
        age:$age
        isArchive:$isArchive
      }
    ) {
      name
    }
  }
`;

export const STUDENT_REMOVE_MUTATION = gql`
  mutation removeStudent {
    removeStudent(id: "3744f556-2a0e-4c1e-bdb7-80d1abb5fdcb") {
      name
      id
    }
  }
`;
