import '@progress/kendo-theme-default/dist/all.css';
import './App.css';
import DataTable from './components/dataTable';

const App = () => {
    return (
        <>
            <div className='App-Header'>
                <h1>LaMaey</h1>
            </div>
            <DataTable />;
        </>
    );
};

export default App;
