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
import { Bar, Radar } from 'react-chartjs-2';

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
                <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    if (!data) {
        return (
            <div className="flex flex-col items-center justify-center h-96">
                <BarChart3 size={48} className="text-red-400 mb-4" />
                <p className="text-slate-400 mb-4">Failed to load model metrics. Start the backend or retry.</p>
                <button
                    onClick={fetchModelMetrics}
                    className="px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-sm font-medium hover:bg-cyan-500/30 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }

    const modelKeys = data.models ? Object.keys(data.models) : [];
    const model = data.models?.[activeModel] || (modelKeys[0] && data.models[modelKeys[0]]);
    const info = data.training_info || {};

    if (!model && modelKeys.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-96">
                <BarChart3 size={48} className="text-slate-500 mb-4" />
                <p className="text-slate-400">No model metrics available. Train models and restart the backend.</p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-xl font-bold text-white flex items-center gap-2">
                    <BarChart3 size={20} className="text-cyan-400" />
                    Model Performance
                </h1>
                <p className="text-xs text-slate-400 mt-1">
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
                        className={`px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200 ${activeModel === key
                                ? 'bg-gradient-to-r from-cyan-500/20 to-purple-500/20 text-cyan-400 border border-cyan-500/30'
                                : 'bg-dark-700 text-slate-400 border border-white/5 hover:text-white hover:border-white/10'
                            }`}
                    >
                        {m?.name ?? key}
                    </button>
                    );
                })}
            </div>

            {/* Metrics Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <MetricCard label="Accuracy" value={model.accuracy} color="cyan" icon={Target} />
                <MetricCard label="Precision" value={model.precision} color="purple" icon={Crosshair} />
                <MetricCard label="Recall" value={model.recall} color="green" icon={Layers} />
                <MetricCard label="F1-Score" value={model.f1_score} color="pink" icon={GitBranch} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Confusion Matrix */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4">Confusion Matrix</h3>
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr>
                                    <th className="text-xs text-slate-500 p-2"></th>
                                    {model.classes.map((c) => (
                                        <th key={c} className="text-xs text-slate-400 p-2 text-center font-medium">
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
                                            <td className="text-xs text-slate-400 p-2 font-medium whitespace-nowrap">{model.classes[i]}</td>
                                            {row.map((val, j) => {
                                                const intensity = val / rowMax;
                                                const isDiag = i === j;
                                                return (
                                                    <td
                                                        key={j}
                                                        className="p-2 text-center"
                                                    >
                                                        <div
                                                            className={`rounded-lg p-2 text-xs font-mono font-semibold transition-all ${isDiag ? 'text-white' : 'text-slate-300'
                                                                }`}
                                                            style={{
                                                                background: isDiag
                                                                    ? `rgba(0, 212, 255, ${0.15 + intensity * 0.35})`
                                                                    : `rgba(239, 68, 68, ${intensity * 0.2})`,
                                                                border: isDiag ? '1px solid rgba(0, 212, 255, 0.2)' : '1px solid transparent',
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
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4">Metrics Comparison</h3>
                    <div className="h-72">
                        <Radar
                            data={{
                                labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC AUC'],
                                datasets: Object.entries(data.models).map(([key, m], i) => ({
                                    label: m.name,
                                    data: [m.accuracy, m.precision, m.recall, m.f1_score, m.roc_auc],
                                    borderColor: ['#00d4ff', '#8b5cf6', '#10b981'][i],
                                    backgroundColor: ['rgba(0,212,255,0.08)', 'rgba(139,92,246,0.08)', 'rgba(16,185,129,0.08)'][i],
                                    borderWidth: 2,
                                    pointRadius: 3,
                                    pointBackgroundColor: ['#00d4ff', '#8b5cf6', '#10b981'][i],
                                })),
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    r: {
                                        min: 0.8,
                                        max: 1,
                                        ticks: { color: '#64748b', font: { size: 9 }, backdropColor: 'transparent', stepSize: 0.05 },
                                        pointLabels: { color: '#94a3b8', font: { size: 11, family: 'Inter' } },
                                        grid: { color: 'rgba(255,255,255,0.05)' },
                                        angleLines: { color: 'rgba(255,255,255,0.05)' },
                                    },
                                },
                                plugins: {
                                    legend: {
                                        labels: { color: '#94a3b8', font: { size: 11 }, usePointStyle: true, pointStyleWidth: 8 },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* ROC AUC + Training Info */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* ROC AUC */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4">ROC AUC Score</h3>
                    <div className="flex items-center justify-center py-8">
                        <div className="relative w-40 h-40">
                            <svg viewBox="0 0 100 100" className="transform -rotate-90">
                                <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="6" />
                                <circle
                                    cx="50" cy="50" r="42" fill="none"
                                    stroke="url(#auc-gradient)"
                                    strokeWidth="6"
                                    strokeLinecap="round"
                                    strokeDasharray={`${model.roc_auc * 264} 264`}
                                    className="transition-all duration-1000"
                                />
                                <defs>
                                    <linearGradient id="auc-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                        <stop offset="0%" stopColor="#00d4ff" />
                                        <stop offset="100%" stopColor="#8b5cf6" />
                                    </linearGradient>
                                </defs>
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className="text-3xl font-bold gradient-text">{model.roc_auc.toFixed(3)}</span>
                                <span className="text-[10px] text-slate-400 uppercase tracking-wider">AUC Score</span>
                            </div>
                        </div>
                    </div>
                    <p className="text-center text-xs text-slate-400 mt-2">
                        {model.roc_auc > 0.95 ? 'Excellent discrimination ability' : model.roc_auc > 0.90 ? 'Good discrimination ability' : 'Fair discrimination ability'}
                    </p>
                </div>

                {/* Training Info */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4">Training Information</h3>
                    <div className="space-y-4">
                        {[
                            { label: 'Dataset', value: info.dataset, icon: Database },
                            { label: 'Total Samples', value: (info.total_samples ?? 0).toLocaleString(), icon: Layers },
                            { label: 'Training Samples', value: (info.training_samples ?? 0).toLocaleString(), icon: GitBranch },
                            { label: 'Test Samples', value: (info.test_samples ?? 0).toLocaleString(), icon: Target },
                            { label: 'Features', value: info.feature_count, icon: Crosshair },
                            { label: 'Last Trained', value: new Date(info.last_trained).toLocaleDateString(), icon: Clock },
                        ].map((item) => (
                            <div key={item.label} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                                <div className="flex items-center gap-2">
                                    <item.icon size={14} className="text-slate-500" />
                                    <span className="text-sm text-slate-400">{item.label}</span>
                                </div>
                                <span className="text-sm font-medium text-white font-mono">{item.value}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Per-Model Comparison Bar */}
            <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-4">Model Comparison</h3>
                <div className="h-64">
                    <Bar
                        data={{
                            labels: Object.values(data.models).map((m) => m.name),
                            datasets: [
                                {
                                    label: 'Accuracy',
                                    data: Object.values(data.models).map((m) => m.accuracy),
                                    backgroundColor: '#00d4ff40',
                                    borderColor: '#00d4ff',
                                    borderWidth: 1,
                                    borderRadius: 4,
                                },
                                {
                                    label: 'Precision',
                                    data: Object.values(data.models).map((m) => m.precision),
                                    backgroundColor: '#8b5cf640',
                                    borderColor: '#8b5cf6',
                                    borderWidth: 1,
                                    borderRadius: 4,
                                },
                                {
                                    label: 'Recall',
                                    data: Object.values(data.models).map((m) => m.recall),
                                    backgroundColor: '#10b98140',
                                    borderColor: '#10b981',
                                    borderWidth: 1,
                                    borderRadius: 4,
                                },
                                {
                                    label: 'F1-Score',
                                    data: Object.values(data.models).map((m) => m.f1_score),
                                    backgroundColor: '#ec489940',
                                    borderColor: '#ec4899',
                                    borderWidth: 1,
                                    borderRadius: 4,
                                },
                            ],
                        }}
                        options={{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11 } } },
                                y: { min: 0.85, max: 1, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 10 } } },
                            },
                            plugins: {
                                legend: {
                                    labels: { color: '#94a3b8', font: { size: 11 }, usePointStyle: true, pointStyleWidth: 8 },
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
        cyan: { text: 'text-cyan-400', bg: 'from-cyan-500/10 to-cyan-500/5', border: 'border-cyan-500/20', bar: 'bg-cyan-500' },
        purple: { text: 'text-purple-400', bg: 'from-purple-500/10 to-purple-500/5', border: 'border-purple-500/20', bar: 'bg-purple-500' },
        green: { text: 'text-green-400', bg: 'from-green-500/10 to-green-500/5', border: 'border-green-500/20', bar: 'bg-green-500' },
        pink: { text: 'text-pink-400', bg: 'from-pink-500/10 to-pink-500/5', border: 'border-pink-500/20', bar: 'bg-pink-500' },
    };
    const c = colorMap[color];

    return (
        <div className={`glass-card p-4 bg-gradient-to-br ${c.bg} border ${c.border} animate-slide-up`}>
            <div className="flex items-center gap-2 mb-2">
                <Icon size={14} className={c.text} />
                <span className="text-xs text-slate-400 font-medium">{label}</span>
            </div>
            <p className={`text-2xl font-bold ${c.text} mb-2`}>{(value * 100).toFixed(1)}%</p>
            <div className="h-1.5 rounded-full bg-dark-700 overflow-hidden">
                <div className={`h-full rounded-full ${c.bar} transition-all duration-1000`} style={{ width: `${pct}%` }} />
            </div>
        </div>
    );
}
