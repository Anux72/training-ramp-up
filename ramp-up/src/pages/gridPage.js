import React, { useState } from "react";
import { useQuery } from "@apollo/client";
import { STUDENT_GET_QUERY } from "../gql/resolvers";

export const StudentInfo = () => {
    const { loading, error, data } = useQuery(STUDENT_GET_QUERY);

    return data.getAllStudents
}