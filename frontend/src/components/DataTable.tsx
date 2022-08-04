import {
  Grid,
  GridCellProps,
  GridColumn,
  GridItemChangeEvent,
  GridToolbar,
} from '@progress/kendo-react-grid';
import '@progress/kendo-theme-default/dist/all.css';
import { useEffect, useRef, useState } from 'react';
import { Student } from '../interfaces/interfaces';
import MyCommandCell from './MyCommandCell';

const editField: string = 'inEdit';

const DataTable = () => {
  const mount = useRef(false);
  const API_URL = 'http://localhost:5000/student/';
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    if (!mount.current) {
      getItems();
    }

    return () => {
      mount.current = true;
    };
  }, []);

  // modify the data in the store, db etc
  const remove = async (dataItem: Student) => {
    await fetch(API_URL + dataItem.id, {
      method: 'DELETE',
    });
    getItems();
  };

  const add = async (dataItem: Student) => {
    dataItem.inEdit = false;
    await fetch(API_URL, {
      method: 'POST',
      body: JSON.stringify(dataItem),
      headers: {
        'Content-type': 'application/json',
      },
    });
    getItems();
  };

  const update = async (dataItem: Student) => {
    dataItem.inEdit = false;
    await fetch(API_URL + dataItem.id, {
      method: 'PATCH',
      body: JSON.stringify(dataItem),
      headers: {
        'Content-type': 'application/json',
      },
    });

    getItems();
  };

  // Local state operations
  const discard = async () => {
    const newData = [...data];
    newData.splice(0, 1);
    setData(newData);
  };

  const cancel = (dataItem: Student) => {
    const id = dataItem.id;
    dataItem.inEdit = false;
    const filteredArry = data.filter((obj: Student) => obj.id !== id);
    filteredArry.unshift(dataItem);
    setData(filteredArry);
  };

  const enterEdit = (dataItem: Student) => {
    setData(
      data.map((item) =>
        item.id === dataItem.id ? { ...item, inEdit: true } : item
      )
    );
  };

  const itemChange = (event: GridItemChangeEvent) => {
    const newData = data.map((item) =>
      item.id === event.dataItem.id
        ? { ...item, [event.field || '']: event.value }
        : item
    );

    setData(newData);
  };

  const addNew = () => {
    const newDataItem = { inEdit: true };
    setData([newDataItem, ...data]);
  };

  const CommandCell = (props: GridCellProps) => (
    <MyCommandCell
      {...props}
      edit={enterEdit}
      remove={remove}
      add={add}
      discard={discard}
      update={update}
      cancel={cancel}
      editField={editField}
    />
  );

  const getItems = async () => {
    let student: Student[] = [];

    const response = await fetch(API_URL);
    if (!response.ok) throw new Error('Something went wrong!');
    const data = await response.json();
    student = data.map((obj: any) => {
      const dateOfBirth = new Date(obj.dateOfBirth);

      return { ...obj, dateOfBirth };
    });
    setData(student);
  };

  return (
    <Grid data={data} onItemChange={itemChange} editField={editField}>
      <GridToolbar>
        <button
          title='Add new'
          className='k-button k-button-md k-rounded-md k-button-solID k-button-solID-primary'
          onClick={addNew}
        >
          Add new
        </button>
      </GridToolbar>
      <GridColumn field='name' title='Name' width='200px' />
      <GridColumn field='gender' title='Gender' />
      <GridColumn field='address' title='Address' width='200px' />
      <GridColumn field='mobileNo' title='MobileNo' />
      <GridColumn
        field='dateOfBirth'
        title='Date Of Birth'
        editor='date'
        format='{0:d}'
        width='150px'
      />
      <GridColumn field='age' title='Age' editor='numeric' />
      {/* <GridColumn field='Discontinued' title='Discontinued' editor='boolean' /> */}
      <GridColumn cell={CommandCell} title='Commands' width='200px' />
    </Grid>
  );
};

export default DataTable;
