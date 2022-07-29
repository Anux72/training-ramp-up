import "./App.css";
import GridPage from "./pages/gridPage";
import "@progress/kendo-theme-default/dist/all.css";
import { Grid, GridColumn, GridToolbar } from "@progress/kendo-react-grid";
import { useEffect, useState } from "react";
import { Commands } from "./pages/commandCell";
import { useQuery, gql, rewriteURIForGET, useMutation } from "@apollo/client";
import { STUDENT_ADD_MUTATION, STUDENT_GET_QUERY } from "./gql/resolvers";

import {
  insertStudent,
  getStudents,
  deleteStudent,
  updateStudent,
} from "./pages/operations";

const editField = "inEdit";


function App() {
  const [stdData, setStdData] = useState([]);
  const { loading, error, data } = useQuery(STUDENT_GET_QUERY);  
  const [addStudent, {data: newStdData }] = useMutation(STUDENT_ADD_MUTATION)

  useEffect(() => {
    let newStudents = getStudents();
    setStdData(newStudents);
  }, []);

  if (loading) return "Loading... ";
  if (error) return console.log(error.message);

  console.log(data);

  const commandCell = (props) => {
    return (
      <Commands
        {...props}
        edit={Edit}
        remove={Remove}
        add={Add}
        discard={Discard}
        update={update}
        cancel={cancel}
        editField={editField}
      />
    );
  };

  //CRUD OPERATIONS
  const Edit = (studentData) => {
    let newData = data.getAllStudents.map((student) =>
      student.Student_id === studentData.Student_id
        ? {
            ...student,
            inEdit: true,
          }
        : student
    );
    setStdData(newData);
  };

  const Add = (student) => {
    student.inEdit = true;
    const newData = insertStudent(student);
    setStdData(newData);
  };

  const Remove = (student) => {
    const newData = [...deleteStudent(student)];
    setStdData(newData);
  };
  const update = (student) => {
    student.inEdit = false;
    const newData = updateStudent(student);
    setStdData(newData);
  };

  const Discard = () => {
    const newData = [...data];
    newData.splice(0, 1);
    setStdData(newData);
  };
  const cancel = (student) => {
    const StudentoriginalData = getStudents().find(
      (S) => S.Student_id === student.Student_id
    );
    const newData = data.getAllStudents.map((Student) =>
      Student.Student_id === StudentoriginalData.Student_id
        ? StudentoriginalData
        : Student
    );
    setStdData(newData);
  };

  const AddNewStudent = () => {
    const newStudentData = {
      inEdit: true,
    };
    setStdData([newStudentData, ...stdData]);
  };

  const itemChange = (event) => {
    const field = event.field || "";
    const newData = data.getAllStudents.map((student) =>
      student.Student_id === event.dataItem.Student_id
        ? { ...student, [field]: event.value }
        : student
    );
    setStdData(newData);
  };

  return (
    <div>
      <h1>Student Records</h1>
      
      
      {/* Initializing the Grid */}
      <Grid
        data={data.getAllStudents}
        editField={editField}
        onItemChange={itemChange}
        dataItemKey={"Student_id"}
      >
        <GridToolbar>
          <button
            title="Add new"
            className="k-button k-button-md k-rounded-md k-button-solid k-button-solid-primary"
            onClick={AddNewStudent}
          >
            Add new
          </button>
        </GridToolbar>
        <GridColumn field="Student_id" title="ID" editable={false} />
        <GridColumn field="name" title="Name" />
        <GridColumn field="gender" title="Gender" />
        <GridColumn field="address" title="Address" />
        <GridColumn field="mobileNo" title="Mobile No" editor="numeric" />
        <GridColumn
          field="DOB"
          title="Date of Birth"
          editor="date"
          format="{0:d}"
        />
        <GridColumn field="age" title="Age" editor="numeric" />
        <GridColumn cell={commandCell} title="Command" width={"240px"} />
      </Grid>
    </div>
  );
}

export default App;
