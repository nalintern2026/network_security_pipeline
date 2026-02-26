import { useState, useEffect } from 'react';
import { getAnomalies } from '../services/api';
import {
    AlertTriangle,
    TrendingUp,
    Zap,
    Eye,
    Filter,
    Search,
    ChevronLeft,
    ChevronRight,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const chartColors = ['#ef4444', '#f59e0b', '#8b5cf6', '#00d4ff', '#10b981', '#ec4899'];

export default function Anomalies() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filters, setFilters] = useState({
        classification: '',
        risk_level: '',
        src_ip: '',
        protocol: '',
    });
    const [page, setPage] = useState(1);

    const fetchAnomalies = async () => {
        setLoading(true);
        try {
            const params = { page, per_page: 20 };
            if (filters.classification?.trim()) params.classification = filters.classification.trim();
            if (filters.risk_level?.trim()) params.risk_level = filters.risk_level.trim();
            if (filters.src_ip?.trim()) params.src_ip = filters.src_ip.trim();
            if (filters.protocol?.trim()) params.protocol = filters.protocol.trim();
            const { data: d } = await getAnomalies(params);
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
    }, [page, filters]);

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
                    Threat detection results from uploaded flows — {data.total_anomalies} threats detected
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
                    Top Threats (Highest Score)
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                    <div className="relative">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                            type="text"
                            placeholder="Source IP..."
                            value={filters.src_ip}
                            onChange={(e) => { setFilters((p) => ({ ...p, src_ip: e.target.value })); setPage(1); }}
                            className="w-full pl-9 pr-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/30 transition-colors"
                        />
                    </div>
                    <select
                        value={filters.classification}
                        onChange={(e) => { setFilters((p) => ({ ...p, classification: e.target.value })); setPage(1); }}
                        className="px-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white focus:outline-none focus:border-cyan-500/30 appearance-none cursor-pointer"
                    >
                        <option value="">All Threat Types</option>
                        {Object.keys(data.attack_breakdown || {}).map((c) => (
                            <option key={c} value={c}>{c}</option>
                        ))}
                    </select>
                    <select
                        value={filters.risk_level}
                        onChange={(e) => { setFilters((p) => ({ ...p, risk_level: e.target.value })); setPage(1); }}
                        className="px-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white focus:outline-none focus:border-cyan-500/30 appearance-none cursor-pointer"
                    >
                        <option value="">All Risk Levels</option>
                        {['Critical', 'High', 'Medium', 'Low'].map((r) => (
                            <option key={r} value={r}>{r}</option>
                        ))}
                    </select>
                    <input
                        type="text"
                        placeholder="Protocol..."
                        value={filters.protocol}
                        onChange={(e) => { setFilters((p) => ({ ...p, protocol: e.target.value })); setPage(1); }}
                        className="px-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/30"
                    />
                    <button
                        onClick={() => { setFilters({ classification: '', risk_level: '', src_ip: '', protocol: '' }); setPage(1); }}
                        className="px-4 py-2 rounded-xl border border-white/10 text-xs text-slate-400 hover:text-white hover:border-cyan-500/30 transition-colors flex items-center justify-center gap-2"
                    >
                        <Filter size={12} />
                        Clear
                    </button>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full data-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Source IP</th>
                                <th>Dest IP</th>
                                <th>Protocol</th>
                                <th>Classification</th>
                                <th>Threat Type</th>
                                <th>CVE</th>
                                <th>Anomaly Score</th>
                                <th>Confidence</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.top_anomalies || []).length === 0 ? (
                                <tr>
                                    <td colSpan={10} className="text-center py-8 text-slate-400 text-sm">
                                        No threats in current data for selected filters.
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
                                    <td className="text-xs font-semibold text-red-400" title={a.classification_reason || ''}>{a.classification}</td>
                                    <td className="text-xs text-amber-200">{a.threat_type || '—'}</td>
                                    <td className="text-xs font-mono text-cyan-300">{a.cve_refs ? String(a.cve_refs).replace(/,/g, ', ') : '—'}</td>
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
                                    <td className="text-xs text-slate-400">{(((a.confidence ?? 0) * 100)).toFixed(0)}%</td>
                                    <td>
                                        <span className={`px-2 py-0.5 rounded-md text-xs font-medium badge-${(a.risk_level || 'low').toLowerCase()}`} title={a.classification_reason || ''}>
                                            {a.risk_level}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {(data.total_pages || 1) > 1 && (
                    <div className="flex items-center justify-between px-1 pt-4">
                        <p className="text-xs text-slate-400">
                            Page {data.page || 1} / {data.total_pages || 1}
                        </p>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setPage(Math.max(1, (data.page || 1) - 1))}
                                disabled={(data.page || 1) <= 1}
                                className="p-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:border-cyan-500/30 disabled:opacity-30 transition-colors"
                            >
                                <ChevronLeft size={14} />
                            </button>
                            <button
                                onClick={() => setPage(Math.min(data.total_pages || 1, (data.page || 1) + 1))}
                                disabled={(data.page || 1) >= (data.total_pages || 1)}
                                className="p-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:border-cyan-500/30 disabled:opacity-30 transition-colors"
                            >
                                <ChevronRight size={14} />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
