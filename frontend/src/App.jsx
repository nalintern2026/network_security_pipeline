import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Upload from './pages/Upload';
import TrafficAnalysis from './pages/TrafficAnalysis';
import Anomalies from './pages/Anomalies';
import ModelPerformance from './pages/ModelPerformance';
import SBOMSecurity from './pages/SBOMSecurity';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/traffic" element={<TrafficAnalysis />} />
          <Route path="/anomalies" element={<Anomalies />} />
          <Route path="/models" element={<ModelPerformance />} />
          <Route path="/security" element={<SBOMSecurity />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
