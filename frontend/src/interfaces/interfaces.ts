export interface Student {
    id?: string;
    name: string;
    gender: string;
    address: string;
    mobileNo: string;
    dateOfBirth: Date;
    age: number;
    inEdit: boolean;

}

export interface columnInterface {
    title?: string,
    field?: string,
    show?: boolean,
    filter?: "boolean" | "numeric" | "text" | "date" | undefined,
    minWidth?: number,
    minGridWidth?: number,
    locked?: boolean,
    width?: string | number
}

