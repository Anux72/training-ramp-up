import {
  Grid,
  GridCellProps,
  GridColumn,
  GridItemChangeEvent,
  GridToolbar,
} from '@progress/kendo-react-grid';

import * as React from 'react';

import { Student } from '../interfaces/interfaces';
import MyCommandCell from './MyCommandCell';
import {
  deleteItem,
  getItems,
  insertItem,
  updateItem,
} from '../services/services';
import { useState, useEffect } from 'react';

const editField: string = 'inEdit';

const DataTable = () => {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    let newItems = getItems();
    setData(newItems);
  }, []);

  // modify the data in the store, db etc
  const remove = (dataItem: Student) => {
    const newData = [...deleteItem(dataItem)];
    setData(newData);
  };

  const add = (dataItem: Student) => {
    dataItem.inEdit = true;

    const newData = [...insertItem(dataItem)];
    setData(newData);
  };

  const update = (dataItem: Student) => {
    dataItem.inEdit = false;
    const newData = [...updateItem(dataItem)];
    setData(newData);
  };

  // Local state operations
  const discard = () => {
    const newData = [...data];
    newData.splice(0, 1);
    setData(newData);
  };

  const cancel = (dataItem: Student) => {
    const originalItem = getItems().find((p) => p.ID === dataItem.ID);
    const newData = data.map((item) =>
      item.ID === originalItem?.ID ? originalItem : item
    );

    setData(newData);
  };

  const enterEdit = (dataItem: Student) => {
    setData(
      data.map((item) =>
        item.ID === dataItem.ID ? { ...item, inEdit: true } : item
      )
    );
  };

  const itemChange = (event: GridItemChangeEvent) => {
    const newData = data.map((item) =>
      item.ID === event.dataItem.ID
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
      <GridColumn field='ID' title='Id' editable={false} />
      <GridColumn field='Name' title='Name' width='250px' />
      <GridColumn field='Gender' title='Gender' />
      <GridColumn field='Address' title='Address' width='250px' />
      <GridColumn field='MobileNo' title='MobileNo' />
      <GridColumn
        field='DateOfBirth'
        title='Date Of Birth'
        editor='date'
        format='{0:d}'
        width='150px'
      />
      <GridColumn field='Age' title='Age' editor='numeric' />
      {/* <GridColumn field='Discontinued' title='Discontinued' editor='boolean' /> */}
      <GridColumn cell={CommandCell} title='Commands' width='200px' />
    </Grid>
  );
};

export default DataTable;
