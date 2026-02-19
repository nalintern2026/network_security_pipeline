import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const api = axios.create({
    baseURL: API_BASE,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Health
export const checkHealth = () => api.get('/health');

// Dashboard
export const getDashboardStats = () => api.get('/dashboard/stats');

// Traffic
export const getTrafficFlows = (params = {}) => api.get('/traffic/flows', { params });

// Anomalies
export const getAnomalies = () => api.get('/anomalies');

// Model Metrics
export const getModelMetrics = () => api.get('/models/metrics');

// Upload
export const uploadFile = (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
    });
};

// Security / SBOM
export const getSBOM = () => api.get('/security/sbom');
export const getVulnerabilities = () => api.get('/security/vulnerabilities');
export const downloadSBOM = () => `${API_BASE}/security/sbom/download`;

export default api;
