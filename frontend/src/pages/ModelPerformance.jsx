import { useState, useEffect } from 'react';
import { getModelMetrics } from '../services/api';
import {
    BarChart3,
    Target,
    Crosshair,
    Layers,
    Clock,
    Database,
    GitBranch,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, RadialLinearScale, PointElement, LineElement } from 'chart.js';
import { Bar, Doughnut, Radar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, RadialLinearScale, PointElement, LineElement);

export default function ModelPerformance() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [activeModel, setActiveModel] = useState('random_forest');

    const fetchModelMetrics = async () => {
        setLoading(true);
        try {
            const { data: d } = await getModelMetrics();
            setData(d);
        } catch (err) {
            console.error('Failed to fetch model metrics:', err);
            setData(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchModelMetrics();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    if (!data) {
        return (
            <div className="flex flex-col items-center justify-center h-96">
                <BarChart3 size={48} className="text-danger mb-4" />
                <p className="text-text-muted mb-4">Failed to load model metrics. Start the backend or retry.</p>
                <button
                    onClick={fetchModelMetrics}
                    className="px-4 py-2.5 rounded-[10px] border border-primary text-primary text-body font-medium hover:bg-primary/10 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }

    const modelKeys = data.models ? Object.keys(data.models) : [];
    const model = data.models?.[activeModel] || (modelKeys[0] && data.models[modelKeys[0]]);
    const info = data.training_info || {};
    const live = data.live_metrics || {};
    const modelStatus = data.model_status || {};
    const hasTrainingModels = modelKeys.length > 0;
    const totalFlows = live.total_flows || 0;
    const totalAnomalies = live.total_anomalies || 0;
    const normalFlows = Math.max(0, totalFlows - totalAnomalies);
    const riskDist = live.risk_distribution || {};

    if (!hasTrainingModels) {
        return (
            <div className="space-y-8">
                <div>
                    <h1 className="text-h1 font-bold text-text-primary flex items-center gap-2">
                        <BarChart3 size={20} className="text-primary" />
                        Model Performance
                    </h1>
                    <p className="text-body text-text-muted mt-1">
                        Runtime metrics from actual uploaded flow data
                    </p>
                </div>

                <h2 className="section-header">Runtime Overview</h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="glass-card p-6">
                        <p className="text-small text-text-muted">Total Flows</p>
                        <p className="text-2xl font-bold text-text-primary">{totalFlows.toLocaleString()}</p>
                    </div>
                    <div className="glass-card p-6">
                        <p className="text-small text-text-muted">Anomaly Rate</p>
                        <p className="text-2xl font-bold text-danger">{(live.anomaly_rate || 0).toFixed(2)}%</p>
                    </div>
                    <div className="glass-card p-6">
                        <p className="text-small text-text-muted">Avg Risk</p>
                        <p className="text-2xl font-bold text-warning">{Math.round((live.avg_risk_score || 0) * 100)}%</p>
                    </div>
                    <div className="glass-card p-6">
                        <p className="text-small text-text-muted">Avg Confidence</p>
                        <p className="text-2xl font-bold text-primary">{Math.round((live.avg_confidence || 0) * 100)}%</p>
                    </div>
                </div>

                <h2 className="section-header">Traffic & Risk</h2>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="glass-card p-6">
                        <h3 className="text-h2 font-semibold text-text-primary mb-4">Traffic Health Split</h3>
                        <div className="h-72 flex items-center justify-center">
                            <Doughnut
                                data={{
                                    labels: ['Normal', 'Anomalies'],
                                    datasets: [{
                                        data: [normalFlows, totalAnomalies],
                                        backgroundColor: ['#22C55E99', '#EF444499'],
                                        borderColor: ['#22C55E', '#EF4444'],
                                        borderWidth: 1,
                                        spacing: 2,
                                        borderRadius: 4,
                                    }],
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    cutout: '62%',
                                    plugins: {
                                        legend: {
                                            position: 'right',
                                            labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 },
                                        },
                                    },
                                }}
                            />
                        </div>
                    </div>

                    <div className="glass-card p-6">
                        <h3 className="text-h2 font-semibold text-text-primary mb-4">Risk Distribution</h3>
                        <div className="h-72">
                            <Bar
                                data={{
                                    labels: ['Low', 'Medium', 'High', 'Critical'],
                                    datasets: [{
                                        label: 'Flows',
                                        data: [
                                            riskDist.Low || 0,
                                            riskDist.Medium || 0,
                                            riskDist.High || 0,
                                            riskDist.Critical || 0,
                                        ],
                                        backgroundColor: ['#22C55E99', '#F59E0B99', '#F59E0B99', '#EF444499'],
                                        borderColor: ['#22C55E', '#F59E0B', '#F59E0B', '#EF4444'],
                                        borderWidth: 1,
                                        borderRadius: 6,
                                    }],
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    scales: {
                                        x: { grid: { display: false }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                        y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                    },
                                    plugins: { legend: { display: false } },
                                }}
                            />
                        </div>
                    </div>
                </div>

                <h2 className="section-header">Quality & Readiness</h2>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="glass-card p-6">
                        <h3 className="text-h2 font-semibold text-text-primary mb-4">Runtime Quality Metrics</h3>
                        <div className="h-72">
                            <Bar
                                data={{
                                    labels: ['Avg Confidence', 'Avg Risk', 'Anomaly Rate'],
                                    datasets: [{
                                        label: 'Percent',
                                        data: [
                                            (live.avg_confidence || 0) * 100,
                                            (live.avg_risk_score || 0) * 100,
                                            live.anomaly_rate || 0,
                                        ],
                                        backgroundColor: ['#00ADB599', '#F59E0B99', '#EF444499'],
                                        borderColor: ['#00ADB5', '#F59E0B', '#EF4444'],
                                        borderWidth: 1,
                                        borderRadius: 6,
                                    }],
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    scales: {
                                        x: { grid: { display: false }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                        y: {
                                            min: 0,
                                            max: 100,
                                            grid: { color: 'rgba(255,255,255,0.06)' },
                                            ticks: { color: '#B0B5BA', font: { size: 13 }, callback: (v) => `${v}%` },
                                        },
                                    },
                                    plugins: { legend: { display: false } },
                                }}
                            />
                        </div>
                    </div>

                    <div className="glass-card p-6">
                        <h3 className="text-h2 font-semibold text-text-primary mb-4">Model Readiness</h3>
                        <div className="h-72">
                            <Radar
                                data={{
                                    labels: ['Supervised', 'Unsupervised', 'Scaler', 'Data Volume', 'Signal Quality'],
                                    datasets: [{
                                        label: 'Readiness',
                                        data: [
                                            modelStatus.supervised_loaded ? 1 : 0,
                                            modelStatus.unsupervised_loaded ? 1 : 0,
                                            modelStatus.scaler_loaded ? 1 : 0,
                                            Math.min(1, totalFlows / 5000),
                                            Math.max(0, 1 - ((live.anomaly_rate || 0) / 100)),
                                        ],
                                        borderColor: '#A855F7',
                                        backgroundColor: 'rgba(168,85,247,0.12)',
                                        borderWidth: 2,
                                        pointRadius: 3,
                                        pointBackgroundColor: '#A855F7',
                                    }],
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    scales: {
                                        r: {
                                            min: 0,
                                            max: 1,
                                            ticks: { color: '#B0B5BA', font: { size: 11 }, backdropColor: 'transparent', stepSize: 0.2 },
                                            pointLabels: { color: '#B0B5BA', font: { size: 13 } },
                                            grid: { color: 'rgba(255,255,255,0.06)' },
                                            angleLines: { color: 'rgba(255,255,255,0.06)' },
                                        },
                                    },
                                    plugins: { legend: { display: false } },
                                }}
                            />
                        </div>
                    </div>
                </div>

                <h2 className="section-header">Model Status</h2>
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4">Model Status</h3>
                    <div className="space-y-2 text-body">
                        <p className="text-text-primary">Supervised loaded: <span className={modelStatus.supervised_loaded ? 'text-success' : 'text-danger'}>{modelStatus.supervised_loaded ? 'Yes' : 'No'}</span></p>
                        <p className="text-text-primary">Unsupervised loaded: <span className={modelStatus.unsupervised_loaded ? 'text-success' : 'text-danger'}>{modelStatus.unsupervised_loaded ? 'Yes' : 'No'}</span></p>
                        <p className="text-text-primary">Scaler loaded: <span className={modelStatus.scaler_loaded ? 'text-success' : 'text-danger'}>{modelStatus.scaler_loaded ? 'Yes' : 'No'}</span></p>
                        <p className="text-text-muted text-small mt-3">No offline training metrics file with model scores found.</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-8">
            {/* Header */}
            <div>
                <h1 className="text-h1 font-bold text-text-primary flex items-center gap-2">
                    <BarChart3 size={20} className="text-primary" />
                    Model Performance
                </h1>
                <p className="text-body text-text-muted mt-1">
                    ML model evaluation metrics and training information
                </p>
            </div>

            {/* Model Selector */}
            <div className="flex gap-2">
                {modelKeys.map((key) => {
                    const m = data.models[key];
                    return (
                    <button
                        key={key}
                        onClick={() => setActiveModel(key)}
                        className={`px-4 py-2 rounded-[10px] text-body font-medium transition-colors ${activeModel === key
                                ? 'bg-primary/15 text-primary border border-primary/30'
                                : 'bg-surface text-text-muted border border-white/10 hover:text-text-primary hover:border-primary/35'
                            }`}
                    >
                        {m?.name ?? key}
                    </button>
                    );
                })}
            </div>

            {/* Metrics Cards */}
            <h2 className="section-header">Model Metrics</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <MetricCard label="Accuracy" value={model.accuracy} color="cyan" icon={Target} />
                <MetricCard label="Precision" value={model.precision} color="purple" icon={Crosshair} />
                <MetricCard label="Recall" value={model.recall} color="green" icon={Layers} />
                <MetricCard label="F1-Score" value={model.f1_score} color="pink" icon={GitBranch} />
            </div>

            <h2 className="section-header">Confusion & Comparison</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Confusion Matrix */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4">Confusion Matrix</h3>
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr>
                                    <th className="text-small text-text-muted p-2"></th>
                                    {model.classes.map((c) => (
                                        <th key={c} className="text-small text-text-muted p-2 text-center font-medium">
                                            {c}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {model.confusion_matrix.map((row, i) => {
                                    const rowMax = Math.max(...row);
                                    return (
                                        <tr key={i}>
                                            <td className="text-small text-text-muted p-2 font-medium whitespace-nowrap">{model.classes[i]}</td>
                                            {row.map((val, j) => {
                                                const intensity = val / rowMax;
                                                const isDiag = i === j;
                                                return (
                                                    <td
                                                        key={j}
                                                        className="p-2 text-center"
                                                    >
                                                        <div
                                                            className={`rounded-lg p-2 text-small font-mono font-semibold transition-all ${isDiag ? 'text-text-primary' : 'text-text-muted'}`}
                                                            style={{
                                                                background: isDiag
                                                                    ? `rgba(0, 173, 181, ${0.15 + intensity * 0.35})`
                                                                    : `rgba(239, 68, 68, ${intensity * 0.2})`,
                                                                border: isDiag ? '1px solid rgba(0, 173, 181, 0.25)' : '1px solid transparent',
                                                            }}
                                                        >
                                                            {val.toLocaleString()}
                                                        </div>
                                                    </td>
                                                );
                                            })}
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Metrics Radar */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4">Metrics Comparison</h3>
                    <div className="h-72">
                        <Radar
                            data={{
                                labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC AUC'],
                                datasets: Object.entries(data.models).map(([key, m], i) => {
                                    const palette = ['#00ADB5', '#A855F7', '#22C55E', '#3B82F6', '#F59E0B'];
                                    const col = palette[i % palette.length];
                                    return {
                                        label: m.name,
                                        data: [m.accuracy, m.precision, m.recall, m.f1_score, m.roc_auc],
                                        borderColor: col,
                                        backgroundColor: col + '20',
                                        borderWidth: 2,
                                        pointRadius: 3,
                                        pointBackgroundColor: col,
                                    };
                                }),
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    r: {
                                        min: 0.8,
                                        max: 1,
                                        ticks: { color: '#B0B5BA', font: { size: 11 }, backdropColor: 'transparent', stepSize: 0.05 },
                                        pointLabels: { color: '#B0B5BA', font: { size: 13, family: 'Inter' } },
                                        grid: { color: 'rgba(255,255,255,0.06)' },
                                        angleLines: { color: 'rgba(255,255,255,0.06)' },
                                    },
                                },
                                plugins: {
                                    legend: {
                                        labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* ROC AUC + Training Info */}
            <h2 className="section-header">ROC & Training</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* ROC AUC */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4">ROC AUC Score</h3>
                    <div className="flex items-center justify-center py-8">
                        <div className="relative w-40 h-40">
                            <svg viewBox="0 0 100 100" className="transform -rotate-90">
                                <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
                                <circle
                                    cx="50" cy="50" r="42" fill="none"
                                    stroke="#00ADB5"
                                    strokeWidth="6"
                                    strokeLinecap="round"
                                    strokeDasharray={`${model.roc_auc * 264} 264`}
                                    className="transition-all duration-500"
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className="text-3xl font-bold text-primary">{model.roc_auc.toFixed(3)}</span>
                                <span className="text-small text-text-muted uppercase tracking-wider">AUC Score</span>
                            </div>
                        </div>
                    </div>
                    <p className="text-center text-small text-text-muted mt-2">
                        {model.roc_auc > 0.95 ? 'Excellent discrimination ability' : model.roc_auc > 0.90 ? 'Good discrimination ability' : 'Fair discrimination ability'}
                    </p>
                </div>

                {/* Training Info */}
                <div className="glass-card p-6">
                    <h3 className="text-h2 font-semibold text-text-primary mb-4">Training Information</h3>
                    <div className="space-y-4">
                        {[
                            { label: 'Dataset', value: info.dataset, icon: Database },
                            { label: 'Total Samples', value: (info.total_samples ?? 0).toLocaleString(), icon: Layers },
                            { label: 'Training Samples', value: (info.training_samples ?? 0).toLocaleString(), icon: GitBranch },
                            { label: 'Test Samples', value: (info.test_samples ?? 0).toLocaleString(), icon: Target },
                            { label: 'Features', value: info.feature_count, icon: Crosshair },
                            { label: 'Last Trained', value: new Date(info.last_trained).toLocaleDateString(), icon: Clock },
                        ].map((item) => (
                            <div key={item.label} className="flex items-center justify-between py-2 border-b border-white/10 last:border-0">
                                <div className="flex items-center gap-2">
                                    <item.icon size={14} className="text-text-muted" />
                                    <span className="text-body text-text-muted">{item.label}</span>
                                </div>
                                <span className="text-body font-medium text-text-primary font-mono">{item.value}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Per-Model Comparison Bar */}
            <h2 className="section-header">Model Comparison</h2>
            <div className="glass-card p-6">
                <h3 className="text-h2 font-semibold text-text-primary mb-4">Model Comparison</h3>
                <div className="h-64">
                    <Bar
                        data={{
                            labels: Object.values(data.models).map((m) => m.name),
                            datasets: [
                                { label: 'Accuracy', data: Object.values(data.models).map((m) => m.accuracy), backgroundColor: '#00ADB599', borderColor: '#00ADB5', borderWidth: 1, borderRadius: 4 },
                                { label: 'Precision', data: Object.values(data.models).map((m) => m.precision), backgroundColor: '#A855F799', borderColor: '#A855F7', borderWidth: 1, borderRadius: 4 },
                                { label: 'Recall', data: Object.values(data.models).map((m) => m.recall), backgroundColor: '#22C55E99', borderColor: '#22C55E', borderWidth: 1, borderRadius: 4 },
                                { label: 'F1-Score', data: Object.values(data.models).map((m) => m.f1_score), backgroundColor: '#3B82F699', borderColor: '#3B82F6', borderWidth: 1, borderRadius: 4 },
                            ],
                        }}
                        options={{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                x: { grid: { display: false }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                                y: { min: 0.85, max: 1, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#B0B5BA', font: { size: 13 } } },
                            },
                            plugins: {
                                legend: {
                                    labels: { color: '#B0B5BA', font: { size: 13 }, usePointStyle: true, pointStyleWidth: 8 },
                                },
                            },
                        }}
                    />
                </div>
            </div>
        </div>
    );
}

function MetricCard({ label, value, color, icon: Icon }) {
    const pct = Math.round(value * 100);
    const colorMap = {
        cyan: { text: 'text-primary', border: 'border-primary/20', bar: 'bg-primary' },
        purple: { text: 'text-[#A855F7]', border: 'border-[#A855F7]/20', bar: 'bg-[#A855F7]' },
        green: { text: 'text-success', border: 'border-success/20', bar: 'bg-success' },
        pink: { text: 'text-[#EC4899]', border: 'border-[#EC4899]/20', bar: 'bg-[#EC4899]' },
    };
    const c = colorMap[color] || colorMap.cyan;

    return (
        <div className={`glass-card p-6 border ${c.border} animate-slide-up`}>
            <div className="flex items-center gap-2 mb-2">
                <Icon size={14} className={c.text} />
                <span className="text-small text-text-muted font-medium">{label}</span>
            </div>
            <p className={`text-2xl font-bold ${c.text} mb-2`}>{(value * 100).toFixed(1)}%</p>
            <div className="h-1.5 rounded-full bg-background overflow-hidden">
                <div className={`h-full rounded-full ${c.bar} transition-all duration-500`} style={{ width: `${pct}%` }} />
            </div>
        </div>
    );
}
