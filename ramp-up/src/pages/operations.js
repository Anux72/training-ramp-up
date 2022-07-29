import { useDispatch } from "react-redux";
import { studentData } from "../data";

let data = [...studentData];

const generateId = (data) =>
  data.reduce((acc, current) => Math.max(acc, current.Student_id), 0) + 1;
// const generateId = data(data.length -1).Student_id +1
export const insertStudent = (student) => {
  student.Student_id = generateId(data);
  student.inEdit = false;
  data.unshift(student);
  return data;
};
export const getStudents = () => {
  return data;
};
export const updateStudent = (student) => {
  let index = data.findIndex(
    (record) => record.Student_id === student.Student_id
  );
  data[index] = student;
  return data;
};
export const deleteStudent = (student) => {
  let index = data.findIndex(
    (record) => record.Student_id === student.Student_id
  );

  data.splice(index, 1);

  return data;
};
