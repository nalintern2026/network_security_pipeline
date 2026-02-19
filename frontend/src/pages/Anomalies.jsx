import { useState, useEffect } from 'react';
import { getAnomalies } from '../services/api';
import {
    AlertTriangle,
    TrendingUp,
    Zap,
    Eye,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const chartColors = ['#ef4444', '#f59e0b', '#8b5cf6', '#00d4ff', '#10b981', '#ec4899'];

export default function Anomalies() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchAnomalies = async () => {
        setLoading(true);
        try {
            const { data: d } = await getAnomalies();
            setData(d);
        } catch (err) {
            console.error('Failed to fetch anomalies:', err);
            setData(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAnomalies();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    if (!data && !loading) {
        return (
            <div className="flex flex-col items-center justify-center h-96">
                <AlertTriangle size={48} className="text-red-400 mb-4" />
                <p className="text-slate-400 mb-4">Failed to load anomaly data. Start the backend or retry.</p>
                <button
                    onClick={fetchAnomalies}
                    className="px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-sm font-medium hover:bg-cyan-500/30 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }

    if (!data) return null;

    return (
        <div className="space-y-6">
            {/* Header */}
            <div>
                <h1 className="text-xl font-bold text-white flex items-center gap-2">
                    <AlertTriangle size={20} className="text-red-400" />
                    Anomaly Detection
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                    Isolation Forest anomaly detection results — {data.total_anomalies} anomalies detected
                </p>
            </div>

            {/* KPIs */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="glass-card p-5 bg-gradient-to-br from-red-500/10 to-red-500/5 border border-red-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-red-500/10">
                            <AlertTriangle size={18} className="text-red-400" />
                        </div>
                        <div>
                            <p className="text-xs text-slate-400">Total Anomalies</p>
                            <p className="text-2xl font-bold text-white">{data.total_anomalies}</p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-5 bg-gradient-to-br from-orange-500/10 to-orange-500/5 border border-orange-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-orange-500/10">
                            <Zap size={18} className="text-orange-400" />
                        </div>
                        <div>
                            <p className="text-xs text-slate-400">High Severity (≥0.8)</p>
                            <p className="text-2xl font-bold text-white">
                                {(data.score_distribution['0.9-1.0'] || 0) + (data.score_distribution['0.8-0.9'] || 0)}
                            </p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-5 bg-gradient-to-br from-purple-500/10 to-purple-500/5 border border-purple-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-xl bg-purple-500/10">
                            <TrendingUp size={18} className="text-purple-400" />
                        </div>
                        <div>
                            <p className="text-xs text-slate-400">Attack Types</p>
                            <p className="text-2xl font-bold text-white">
                                {Object.keys(data.attack_breakdown || {}).length}
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Score Distribution */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                        <TrendingUp size={14} className="text-cyan-400" />
                        Anomaly Score Distribution
                    </h3>
                    <div className="h-64">
                        <Bar
                            data={{
                                labels: Object.keys(data.score_distribution),
                                datasets: [{
                                    label: 'Count',
                                    data: Object.values(data.score_distribution),
                                    backgroundColor: ['#ef444440', '#f59e0b40', '#8b5cf640', '#00d4ff40', '#10b98140', '#64748b40'],
                                    borderColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#00d4ff', '#10b981', '#64748b'],
                                    borderWidth: 1,
                                    borderRadius: 6,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8', font: { size: 10 } } },
                                    y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 10 } } },
                                },
                                plugins: { legend: { display: false } },
                            }}
                        />
                    </div>
                </div>

                {/* Attack Breakdown */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                        <Zap size={14} className="text-red-400" />
                        Attack Type Breakdown
                    </h3>
                    <div className="h-64 flex items-center justify-center">
                        <Doughnut
                            data={{
                                labels: Object.keys(data.attack_breakdown || {}),
                                datasets: [{
                                    data: Object.values(data.attack_breakdown || {}),
                                    backgroundColor: chartColors,
                                    borderWidth: 0,
                                    spacing: 2,
                                    borderRadius: 4,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                cutout: '60%',
                                plugins: {
                                    legend: {
                                        position: 'right',
                                        labels: { color: '#94a3b8', font: { size: 11 }, padding: 8, usePointStyle: true, pointStyleWidth: 8 },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Top Anomalies Table */}
            <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                    <Eye size={14} className="text-red-400" />
                    Top Anomalies (Highest Score)
                </h3>
                <div className="overflow-x-auto">
                    <table className="w-full data-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Source IP</th>
                                <th>Dest IP</th>
                                <th>Protocol</th>
                                <th>Classification</th>
                                <th>Anomaly Score</th>
                                <th>Confidence</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.top_anomalies || []).length === 0 ? (
                                <tr>
                                    <td colSpan={7} className="text-center py-8 text-slate-400 text-sm">
                                        No anomalies in current data. Upload a capture or wait for backend to load flow data.
                                    </td>
                                </tr>
                            ) : (data.top_anomalies || []).map((a, i) => (
                                <tr key={a.id}>
                                    <td className="font-mono text-cyan-400 text-xs">#{i + 1}</td>
                                    <td className="font-mono text-xs text-cyan-300">{a.src_ip}</td>
                                    <td className="font-mono text-xs text-slate-300">{a.dst_ip}</td>
                                    <td>
                                        <span className="px-2 py-0.5 rounded-md bg-dark-700 text-xs font-mono text-cyan-400 border border-white/5">
                                            {a.protocol}
                                        </span>
                                    </td>
                                    <td className="text-xs font-semibold text-red-400">{a.classification}</td>
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <div className="h-2 w-16 rounded-full bg-dark-700 overflow-hidden">
                                                <div
                                                    className={`h-full rounded-full ${a.anomaly_score >= 0.9 ? 'bg-red-500' : a.anomaly_score >= 0.8 ? 'bg-orange-500' : 'bg-yellow-500'
                                                        }`}
                                                    style={{ width: `${a.anomaly_score * 100}%` }}
                                                />
                                            </div>
                                            <span className="text-xs font-mono text-red-400">{a.anomaly_score.toFixed(3)}</span>
                                        </div>
                                    </td>
                                    <td className="text-xs text-slate-400">{(a.confidence * 100).toFixed(0)}%</td>
                                    <td>
                                        <span className={`px-2 py-0.5 rounded-md text-xs font-medium badge-${a.risk_level.toLowerCase()}`}>
                                            {a.risk_level}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

