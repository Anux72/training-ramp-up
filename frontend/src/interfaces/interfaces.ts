export interface ProductCategory {
    CategoryID?: number,
    CategoryName?: string,
    Description?: string,
    details?: any
}

export interface Student {
    ID?: number;
    Name: string;
    Gender: string;
    Address: string;
    MobileNo: string;
    DateOfBirth: Date;
    Age: number;
    inEdit?: boolean;
    Discontinued?: boolean;
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

/* export interface OrderShipAddress {
    street: string,
    city: string,
    region: string,
    postalCode: number,
    country: string
}

export interface OrderDetails {
    productID: number,
    unitPrice: number,
    quantity: number,
    discount: number
}
export interface Order {
    orderID: number,
    OrderID?: number,
    customerID: string,
    employeeID: number,
    orderDate?: Date,
    requiredDate: Date,
    shippedDate?: Date,
    shipVia: number,
    freight: number,
    shipName: string,
    shipAddress: OrderShipAddress,
    details: OrderDetails[]
}

export interface Person {
    id: number,
    firstName: string,
    lastName: string,
    city: string,
    title: string
};
 */