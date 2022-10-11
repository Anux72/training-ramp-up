import { store } from "../index";
import * as actions from "../reducer";

export const getBirthday = (birthday) => {
  var date = birthday.split("/");
  var d = parseInt(date[0], 10),
    m = parseInt(date[1], 10),
    y = parseInt(date[2], 10);
  return new Date(y, m - 1, d);
};

export const getAge = (date) => {
  const today = new Date();
  const birthdate = getBirthday(date);
  const currentYear = today.getFullYear();
  const currentMonth = today.getMonth();
  const currentDay = today.getDate();
  const birthYear = birthdate.getFullYear();
  const birthMonth = birthdate.getMonth();
  const birthDay = birthdate.getDate();
  let years = currentYear - birthYear;
  let months = 0;
  let days = 0;
  if (currentMonth >= birthMonth) {
    months = currentMonth - birthMonth;
  } else {
    years--;
    months = 12 + currentMonth - birthMonth;
  }
  if (currentDay >= birthDay) {
    days = currentDay - birthDay;
  } else {
    months--;
    days = 31 + currentDay - birthDay;
  }
  if (months < 0) {
    months = 11;
    years--;
  }
  return `${years} years ${months} months ${days} days`;
};

export const birthdayChange = (value, dataItem) => {
  const { entries } = store.getState();
  const age = getAge(value);
  const newEntry = entries.map((entry) =>
    entry.id === dataItem.id
      ? { ...entry, ["birthday"]: value, ["age"]: age }
      : entry
  );
  store.dispatch(actions.addEntries(newEntry));
};

export const genderChange = (value, dataItem) => {
  const { entries } = store.getState();
  const newEntry = entries.map((entry) =>
    entry.id === dataItem.id ? { ...entry, ["gender"]: value } : entry
  );
  store.dispatch(actions.addEntries(newEntry));
};

export const getGender = (dataItem) => {
  const { entries } = store.getState();
  const gender = entries.find((e) => e.id === dataItem.id).gender;
  return gender;
};

export const discardEntry = () => {
  const { entries } = store.getState();
  const newEntries = [...entries];
  newEntries.splice(0, 1);
  store.dispatch(actions.addUpdatingEntry(null));
  store.dispatch(actions.addChangingEntry(null));
  store.dispatch(actions.addEntries(newEntries));
};

export const cancelChanges = (entry) => {
  const { updatingEntry, entries } = store.getState();
  const index = entries.findIndex((e) => e.id === entry.id);
  const newEntries = [...entries];
  newEntries[index] = updatingEntry;
  store.dispatch(actions.addUpdatingEntry(null));
  store.dispatch(actions.addChangingEntry(null));
  store.dispatch(actions.addEntries(newEntries));
};

export const startEdit = (entry) => {
  const { updatingEntry, entries } = store.getState();
  if (updatingEntry === null) {
    const newEntries = entries.map((e) => {
      if (e.id === entry.id) {
        store.dispatch(actions.addUpdatingEntry(entry));
        store.dispatch(actions.addChangingEntry(entry));
        return { ...e, inEdit: true };
      } else {
        return e;
      }
    });
    store.dispatch(actions.addEntries(newEntries));
  }
};

export const fieldChange = (event) => {
  const { entries } = store.getState();
  const inEditID = event.dataItem.id;
  const field = event.field || "";
  const newEntries = entries.map((entry) =>
    entry.id === inEditID ? { ...entry, [field]: event.value } : entry
  );
  const changingEntry = newEntries.find((e) => e.id === inEditID);
  store.dispatch(actions.addChangingEntry(changingEntry));
  store.dispatch(actions.addEntries(newEntries));
};

export const addEntry = () => {
  const { updatingEntry, entries } = store.getState();
  const date = new Date().toLocaleDateString("en-GB");
  if (updatingEntry === null) {
    const newEntry = {
      birthday: date,
      new: true,
      inEdit: true,
    };
    store.dispatch(actions.addUpdatingEntry(newEntry));
    store.dispatch(actions.addChangingEntry(newEntry));
    store.dispatch(actions.addEntries([newEntry, ...entries]));
  }
};
