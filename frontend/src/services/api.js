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

// Upload in progress – avoid marking "offline" while backend is busy processing large file
let uploadInProgress = false;
export function setUploadInProgress(value) {
    uploadInProgress = Boolean(value);
}
export function isUploadInProgress() {
    return uploadInProgress;
}

// Health – use longer timeout so backend busy with upload doesn't trigger "offline"
const HEALTH_TIMEOUT_MS = 120000; // 2 min when backend may be processing large upload
export const checkHealth = () => {
    return api.get('/health', { timeout: HEALTH_TIMEOUT_MS });
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

// History
export const getHistory = (limit = 100) => api.get('/history', { params: { limit } });
export const getHistoryReport = (analysisId) => api.get(`/history/${analysisId}`);

// Security / SBOM
export const getSBOM = () => api.get('/security/sbom');
export const getVulnerabilities = () => api.get('/security/vulnerabilities');
export const analyzeSBOMFile = (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/security/sbom/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 60000,
    });
};
export const downloadSBOM = () => `${API_BASE}/security/sbom/download`;

export default api;
