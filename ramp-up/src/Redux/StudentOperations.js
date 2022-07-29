import { createSlice } from "@reduxjs/toolkit";
import { studentData } from "../data";

export const studentSlice = createSlice({
    name: "students",
    initialState: {value: studentData},

    reducers: {
        addStudent : (state, action) => {
            state.value.push(action.payload);
        },
        getStudent : (state ,action ) => {
            
        },
        updateStudent : (state, action) => {

        },
        removeStudent : (state, action) => {
            
        }
    }
})


export const {addStudent} = studentSlice.actions;
export default studentSlice.reducer