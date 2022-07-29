import React from "react";
import '@progress/kendo-theme-default/dist/all.css';
import { Grid, GridColumn, GridToolbar } from "@progress/kendo-react-grid";
import { studentData } from "../data";
import { commands } from "./commandCell";

function GridPage() {
    
    const editField = "inEdit"
    const commandCell = props => <commands {...props} edit={Edit} remove={Remove} add={Add} discard={Discard} update={update} cancel={cancel} editField={editField} />;

    //CRUD OPERATIONS
    const Edit = () => {

    }
    const Add = () => {

    }
    const Remove = () => {

    }
    const Discard = () => {

    }

    const update = () => {

    }
    const cancel =() =>{

    }
    return (
        <div>
            <h1>Student Records</h1>
            {/* Initializing the Grid */}
            <Grid data={studentData} editField={editField}>
                <GridToolbar>
                    <button title="Add new" className="k-button k-button-md k-rounded-md k-button-solid k-button-solid-primary" >
                        Add new
                    </button>
                </GridToolbar>
                <GridColumn field="Student_id" title="ID" />
                <GridColumn field="Student_name" title="Name" />
                <GridColumn field="Student_gender" title="Gender" />
                <GridColumn field="Student_address" title="Address" />
                <GridColumn field="Student_mobile" title="Mobile No" />
                <GridColumn field="Student_DOB" title="Date of Birth" editor="date" format="{0:dd/MMMM/yyyy H:mm}" />
                <GridColumn field="Student_age" title="Age" />
                <GridColumn cell={commandCell} title="Command" width={"240px"} />
            </Grid>
        </div>
    )
}

export default GridPage();