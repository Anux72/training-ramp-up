export const ActionCell = (props) => {
    const { dataItem: student } = props;
    const inEdit = student[props.editField];
    const isNewItem = student.stuID === undefined;
    return inEdit ? (
        <td className='k-command-cell'>
            <button
                className='k-button k-button-md k-rounded-md k-button-solid k-button-solid-base k-grid-save-command'
                onClick={() =>
                    isNewItem ? props.add(student) : props.update(student)
                }>
                {isNewItem ? 'Add' : 'Update'}
            </button>
            <button
                className='k-button k-button-md k-rounded-md k-button-solid k-button-solid-base k-grid-cancel-command'
                onClick={() =>
                    isNewItem ? props.discard(student) : props.cancel(student)
                }>
                {isNewItem ? 'Discard' : 'Cancel'}
            </button>
        </td>
    ) : (
        <td className='k-command-cell'>
            <button
                className='k-button k-button-md k-rounded-md k-button-solid k-button-solid-primary k-grid-edit-command'
                onClick={() => props.edit(student)}>
                Edit
            </button>
            <button
                className='k-button k-button-md k-rounded-md k-button-solid k-button-solid-base k-grid-remove-command'
                onClick={() => {
                    props.remove(student);
                }}>
                Remove
            </button>
        </td>
    );
};
