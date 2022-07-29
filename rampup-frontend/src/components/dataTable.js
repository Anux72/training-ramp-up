import {
    Grid,
    GridColumn as Column,
    GridToolbar,
} from "@progress/kendo-react-grid";
import { useEffect, useState } from "react";
import {
    getStudents,
    addStudent,
    updateStudent,
    deleteStudent,
} from "../services/services";
import { useQuery, gql } from "@apollo/client";
import { ActionCell } from "./actionCell";
// {
//     students {
//         stuID
//         name
//         gender
//         address
//         phone
//         dob
//     }
// }

//used dummy data for demo
const FILMS_QUERY = gql`
    {
        launchesPast(limit: 10) {
            id
            mission_name
        }
    }
`;

const DataTable = () => {
    const { data, loading, error } = useQuery(FILMS_QUERY);
    const [datau, setData] = useState([]);

    useEffect(() => {
        let newItems = getStudents();
        setData(newItems);
    }, []);

    const add = (dataItem) => {
        dataItem.inEdit = true;
        const newData = addStudent(dataItem);
        setData(newData);
    };

    const discard = () => {
        const newData = [...datau];
        newData.splice(0, 1);
        setData(newData);
    };

    const update = (dataItem) => {
        dataItem.inEdit = false;
        const newData = updateStudent(dataItem);
        setData(newData);
    };

    const cancel = (dataItem) => {
        const originalItem = getStudents().find(
            (p) => p.stuID === dataItem.stuID
        );
        const newData = datau.map((item) =>
            item.stuID === originalItem.stuID ? originalItem : item
        );
        setData(newData);
    };

    const remove = (dataItem) => {
        const newData = [...deleteStudent(dataItem)];
        setData(newData);
    };

    const addNew = () => {
        const newDataItem = {
            inEdit: true,
        };
        setData([newDataItem, ...datau]);
    };

    const enterEdit = (dataItem) => {
        setData(
            datau.map((student) =>
                student.stuID === dataItem.stuID
                    ? { ...student, inEdit: true }
                    : student
            )
        );
    };

    const itemChange = (event) => {
        const newData = datau.map((item) =>
            item.stuID === event.dataItem.stuID
                ? { ...item, [event.field || ""]: event.value }
                : item
        );
        setData(newData);
    };

    const funcCell = (props) => (
        <ActionCell
            {...props}
            add={add}
            remove={remove}
            editField={"inEdit"}
            discard={discard}
            edit={enterEdit}
            update={update}
            cancel={cancel}
        />
    );

    if (loading) return "Loading...";
    if (error) return <pre>{error.message}</pre>;

    return (
        <Grid
            style={{
                height: "80vh",
            }}
            data={data.launchesPast}
            onItemChange={itemChange}
            editField={"inEdit"}>
            <GridToolbar>
                <button
                    title="Add new"
                    className="k-button k-button-md k-rounded-md k-button-solid k-button-solid-base"
                    onClick={addNew}>
                    Add new
                </button>
            </GridToolbar>
            <Column field="id" title="ID" editable={false} />
            <Column field="mission_name" title="Name" />
            {/* <Column field="gender" title="Gender" />
                <Column field="address" title="Address" />
                <Column field="phone" title="Mobile No" />
                <Column
                    field="dob"
                    title="Date of Birth"
                    editor="date"
                    format="{0:d}"
                />
                <Column field="age" title="Age" editor="numeric" />
                <Column cell={funcCell} width="200px" /> */}
        </Grid>
    );
};
export default DataTable;
