import {
    Grid,
    GridColumn as Column,
    GridToolbar,
} from '@progress/kendo-react-grid';
import { useEffect, useState } from 'react';
import {
    getStudents,
    addStudent,
    updateStudent,
    deleteStudent,
} from '../services/services';
import { ActionCell } from './actionCell';

const DataTable = () => {
    const [data, setData] = useState([]);

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
        const newData = [...data];
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
        const newData = data.map((item) =>
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
        setData([newDataItem, ...data]);
    };

    const enterEdit = (dataItem) => {
        setData(
            data.map((student) =>
                student.stuID === dataItem.stuID
                    ? { ...student, inEdit: true }
                    : student
            )
        );
    };

    const itemChange = (event) => {
        const newData = data.map((item) =>
            item.stuID === event.dataItem.stuID
                ? { ...item, [event.field || '']: event.value }
                : item
        );
        setData(newData);
    };

    const funcCell = (props) => (
        <ActionCell
            {...props}
            add={add}
            remove={remove}
            editField={'inEdit'}
            discard={discard}
            edit={enterEdit}
            update={update}
            cancel={cancel}
        />
    );

    return (
        <Grid
            style={{
                height: '80vh',
            }}
            data={data}
            onItemChange={itemChange}
            editField={'inEdit'}>
            <GridToolbar>
                <button
                    title='Add new'
                    className='k-button k-button-md k-rounded-md k-button-solid k-button-solid-base'
                    onClick={addNew}>
                    Add new
                </button>
            </GridToolbar>
            <Column field='stuID' title='ID' editable={false} />
            <Column field='StudentName' title='Name' />
            <Column field='gender' title='Gender' />
            <Column field='address' title='Address' />
            <Column field='phone' title='Mobile No' />
            <Column
                field='dob'
                title='Date of Birth'
                editor='date'
                format='{0:d}'
            />
            <Column field='age' title='Age' editor='numeric' />
            <Column cell={funcCell} width='200px' />
        </Grid>
    );
};
export default DataTable;
