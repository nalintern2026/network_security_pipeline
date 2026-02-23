import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

console.log('🌐 API Service initialized with API_BASE:', API_BASE);
console.log('🌐 VITE_API_URL env var:', import.meta.env.VITE_API_URL);

const api = axios.create({
    baseURL: API_BASE,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Health
export const checkHealth = () => {
    console.log(`📡 Making GET request to ${API_BASE}/health`);
    return api.get('/health');
};

// Dashboard
export const getDashboardStats = () => {
    const endpoint = '/dashboard/stats';
    console.log(`📡 Making GET request to ${API_BASE}${endpoint}`);
    return api.get(endpoint);
};

// Traffic
export const getTrafficFlows = (params = {}) => api.get('/traffic/flows', { params });
export const getTrafficTrends = (params = {}) => api.get('/traffic/trends', { params });

// Anomalies / Threats
export const getAnomalies = (params = {}) => api.get('/anomalies', { params });

// Model Metrics
export const getModelMetrics = () => api.get('/models/metrics');

// Upload
export const uploadFile = (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 0,
    });
};
export const getUploadFlows = (analysisId, params = {}) => api.get(`/upload/${analysisId}/flows`, { params });

// Security / SBOM
export const getSBOM = () => api.get('/security/sbom');
export const getVulnerabilities = () => api.get('/security/vulnerabilities');
export const downloadSBOM = () => `${API_BASE}/security/sbom/download`;

export default api;
