
import '@progress/kendo-theme-default/dist/all.css';
import './App.css';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import GridPage from './pages/gridPage';




function App() {
  return (
    <div className="App">
      {/* Routes */}
      <BrowserRouter>
        <Routes>
          <Route exact path="/HomeGrid" element={GridPage} />
        </Routes>
      </BrowserRouter>

    </div>
  );
}

export default App;
