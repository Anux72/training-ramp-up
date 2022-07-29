import "./App.css";
import GridPage from "./pages/gridPage";
import "@progress/kendo-theme-default/dist/all.css";
import { Grid, GridColumn, GridToolbar } from "@progress/kendo-react-grid";
import { useEffect, useState } from "react";
import { Commands } from "./pages/commandCell";


import {
  insertStudent,
  getStudents,
  deleteStudent,
  updateStudent,
} from "./pages/operations";

const editField = "inEdit";

function App() {
  const [data, setData] = useState([]);
  

  useEffect(() => {
    let newStudents = getStudents();
    setData(newStudents);
  }, []);

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
    let newData = data.map((student) =>
      student.Student_id === studentData.Student_id
        ? {
            ...student,
            inEdit: true,
          }
        : student
    );
    setData(newData);
  };

  const Add = (student) => {
    student.inEdit = true;
    const newData = insertStudent(student);
    setData(newData);
  };

  const Remove = (student) => {
    const newData = [...deleteStudent(student)];
    setData(newData);
  };
  const update = (student) => {
    student.inEdit = false;
    const newData = updateStudent(student);
    setData(newData);
  };

  const Discard = () => {
    const newData = [...data];
    newData.splice(0, 1);
    setData(newData);
  };
  const cancel = (student) => {
    const StudentoriginalData = getStudents().find(
      (S) => S.Student_id === student.Student_id
    );
    const newData = data.map((Student) =>
      Student.Student_id === StudentoriginalData.Student_id
        ? StudentoriginalData
        : Student
    );
    setData(newData);
  };

  const AddNewStudent = () => {
    const newStudentData = {
      inEdit: true,
    };
    setData([newStudentData, ...data]);
  };

  const itemChange = (event) => {
    const field = event.field || "";
    const newData = data.map((student) =>
      student.Student_id === event.dataItem.Student_id
        ? { ...student, [field]: event.value }
        : student
    );
    setData(newData);
  };

  return (
    <div>
      <h1>Student Records</h1>
      {/* Initializing the Grid */}
      <Grid
        data={data}
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
        <GridColumn field="Student_name" title="Name" />
        <GridColumn field="Student_gender" title="Gender" />
        <GridColumn field="Student_address" title="Address" />
        <GridColumn field="Student_mobile" title="Mobile No" editor="numeric" />
        <GridColumn
          field="Student_DOB"
          title="Date of Birth"
          editor="date"
          format="{0:d}"
        />
        <GridColumn field="Student_age" title="Age" editor="numeric" />
        <GridColumn cell={commandCell} title="Command" width={"240px"} />
      </Grid>
    </div>
  );
}

export default App;
