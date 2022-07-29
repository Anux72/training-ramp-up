import { sampleStudents } from "../components/sample-students";

let data = [...sampleStudents];

const generateId = (data: any[]) =>
    data.reduce((acc, current) => Math.max(acc, current.ID), 0) + 1;

export const insertItem = (item: any) => {
    item.ID = generateId(data);
    item.inEdit = false;
    data.unshift(item);
    return data;
};

export const getItems = () => {
    return data;
};

export const updateItem = (item: any) => {
    let index = data.findIndex(record => record.ID === item.ID);
    data[index] = item;
    return data;
};

export const deleteItem = (item: any) => {
    let index = data.findIndex(record => record.ID === item.ID);
    data.splice(index, 1);
    return data;
};
