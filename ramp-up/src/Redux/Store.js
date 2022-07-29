import {configureStore} from "@reduxjs/toolkit"
import studentReducer from "./StudentOperations"


export default configureStore({
    reducer:{ 
        students: studentReducer
    }
})
