import { useState, useEffect, useCallback } from 'react';
import { getTrafficFlows, getTrafficTrends } from '../services/api';
import {
    Network,
    Search,
    ChevronLeft,
    ChevronRight,
    Filter,
    ArrowUpDown,
} from 'lucide-react';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend } from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

const PROTOCOL_MAP = {
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP',
    '47': 'GRE',
    '50': 'ESP',
    '51': 'AH',
    '89': 'OSPF',
    '132': 'SCTP',
};

const PROTOCOL_OPTIONS = [
    { value: '6', label: 'TCP (6)' },
    { value: '17', label: 'UDP (17)' },
    { value: '1', label: 'ICMP (1)' },
    { value: '47', label: 'GRE (47)' },
    { value: '50', label: 'ESP (50)' },
    { value: '51', label: 'AH (51)' },
    { value: '89', label: 'OSPF (89)' },
    { value: '132', label: 'SCTP (132)' },
];

export default function TrafficAnalysis() {
    const [flows, setFlows] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [trendData, setTrendData] = useState([]);
    const [filters, setFilters] = useState({
        classification: '',
        risk_level: '',
        src_ip: '',
        protocol: '',
    });

    const fetchFlows = useCallback(async ({ silent = false } = {}) => {
        if (!silent) {
            setLoading(true);
        }
        setError(null);
        try {
            const params = { page, per_page: 15 };
            if (filters.classification?.trim()) params.classification = filters.classification.trim();
            if (filters.risk_level?.trim()) params.risk_level = filters.risk_level.trim();
            if (filters.src_ip?.trim()) params.src_ip = filters.src_ip.trim();
            if (filters.protocol?.trim()) params.protocol = filters.protocol.trim();

            const [flowsRes, trendsRes] = await Promise.all([
                getTrafficFlows(params),
                getTrafficTrends({ ...params, points: 96 }),
            ]);
            setFlows(flowsRes.data.flows || []);
            setTotal(flowsRes.data.total ?? 0);
            setTotalPages(Math.max(1, flowsRes.data.total_pages ?? 1));
            setTrendData(trendsRes.data.points || []);
        } catch (err) {
            console.error('Failed to fetch flows:', err);
            setError(err.response?.data?.detail || 'Cannot reach backend. Start the API to see traffic data.');
        } finally {
            if (!silent) {
                setLoading(false);
            }
        }
    }, [page, filters]);

    useEffect(() => {
        fetchFlows();
    }, [fetchFlows]);

    useEffect(() => {
        const interval = setInterval(() => {
            fetchFlows({ silent: true });
        }, 5000);
        return () => clearInterval(interval);
    }, [fetchFlows]);

    const handleFilterChange = (key, value) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
        setPage(1);
    };

    const clearFilters = () => {
        setFilters({ classification: '', risk_level: '', src_ip: '', protocol: '' });
        setPage(1);
    };

    const formatProtocol = (value) => {
        if (value == null) return '—';
        const code = String(value).trim();
        const name = PROTOCOL_MAP[code];
        return name ? `${name} (${code})` : code;
    };

    const trendLabels = trendData.map((p) => {
        const raw = String(p?.hour || '').trim();
        if (!raw) return '';

        let dt = new Date(raw);
        if (Number.isNaN(dt.getTime())) dt = new Date(raw.replace(' ', 'T'));
        if (Number.isNaN(dt.getTime()) && raw.length === 13) dt = new Date(`${raw}:00:00`);
        if (Number.isNaN(dt.getTime()) && raw.length === 16) dt = new Date(`${raw}:00`);
        if (Number.isNaN(dt.getTime())) return raw;

        return dt.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    });

    return (
        <div className="space-y-5">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-xl font-bold text-white flex items-center gap-2">
                        <Network size={20} className="text-cyan-400" />
                        Traffic Analysis
                    </h1>
                    <p className="text-xs text-slate-400 mt-1">
                        {total.toLocaleString()} flows detected
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="glass-card p-4">
                <div className="flex items-center gap-2 mb-3">
                    <Filter size={14} className="text-cyan-400" />
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Filters</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    {/* IP Filter */}
                    <div className="relative">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                            type="text"
                            placeholder="Source IP..."
                            value={filters.src_ip}
                            onChange={(e) => handleFilterChange('src_ip', e.target.value)}
                            className="w-full pl-9 pr-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/30 transition-colors"
                        />
                    </div>

                    {/* Classification */}
                    <select
                        value={filters.classification}
                        onChange={(e) => handleFilterChange('classification', e.target.value)}
                        className="px-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white focus:outline-none focus:border-cyan-500/30 appearance-none cursor-pointer"
                    >
                        <option value="">All Classifications</option>
                        {['Benign', 'Anomaly', 'DDoS', 'PortScan', 'BruteForce', 'Web Attack', 'Bot', 'Infiltration', 'Heartbleed'].map((c) => (
                            <option key={c} value={c}>{c}</option>
                        ))}
                    </select>

                    {/* Risk Level */}
                    <select
                        value={filters.risk_level}
                        onChange={(e) => handleFilterChange('risk_level', e.target.value)}
                        className="px-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white focus:outline-none focus:border-cyan-500/30 appearance-none cursor-pointer"
                    >
                        <option value="">All Risk Levels</option>
                        {['Critical', 'High', 'Medium', 'Low'].map((r) => (
                            <option key={r} value={r}>{r}</option>
                        ))}
                    </select>

                    {/* Protocol */}
                    <select
                        value={filters.protocol}
                        onChange={(e) => handleFilterChange('protocol', e.target.value)}
                        className="px-3 py-2 rounded-xl bg-dark-800 border border-white/5 text-sm text-white focus:outline-none focus:border-cyan-500/30 appearance-none cursor-pointer"
                    >
                        <option value="">All Protocols</option>
                        {PROTOCOL_OPTIONS.map((p) => (
                            <option key={p.value} value={p.value}>{p.label}</option>
                        ))}
                    </select>

                    {/* Clear */}
                    <button
                        onClick={clearFilters}
                        className="px-4 py-2 rounded-xl border border-white/10 text-xs text-slate-400 hover:text-white hover:border-cyan-500/30 transition-colors"
                    >
                        Clear Filters
                    </button>
                </div>
            </div>

            {/* Flow Trend Charts */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <div className="glass-card p-4">
                    <h3 className="text-sm font-semibold text-slate-300 mb-3">Flow Volume & Threat Mix (Averaged by Hour)</h3>
                    <div className="h-72">
                        <Line
                            data={{
                                labels: trendLabels,
                                datasets: [
                                    {
                                        label: 'Total Flows',
                                        data: trendData.map((p) => p.total_flows || 0),
                                        borderColor: '#00d4ff',
                                        backgroundColor: 'rgba(0, 212, 255, 0.08)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Threat Flows',
                                        data: trendData.map((p) => p.threat_flows || 0),
                                        borderColor: '#ef4444',
                                        backgroundColor: 'rgba(239, 68, 68, 0.08)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Benign Flows',
                                        data: trendData.map((p) => p.benign_flows || 0),
                                        borderColor: '#10b981',
                                        backgroundColor: 'rgba(16, 185, 129, 0.08)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                ],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                interaction: { mode: 'index', intersect: false },
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8', maxTicksLimit: 8 } },
                                    y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b' } },
                                },
                                plugins: {
                                    legend: { labels: { color: '#94a3b8', usePointStyle: true, pointStyleWidth: 8 } },
                                },
                            }}
                        />
                    </div>
                </div>

                <div className="glass-card p-4">
                    <h3 className="text-sm font-semibold text-slate-300 mb-3">Average Risk, Confidence & Threat Rate</h3>
                    <div className="h-72">
                        <Line
                            data={{
                                labels: trendLabels,
                                datasets: [
                                    {
                                        label: 'Avg Risk %',
                                        data: trendData.map((p) => Math.round((p.avg_risk_score || 0) * 100)),
                                        borderColor: '#f59e0b',
                                        backgroundColor: 'rgba(245, 158, 11, 0.08)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Avg Confidence %',
                                        data: trendData.map((p) => Math.round((p.avg_confidence || 0) * 100)),
                                        borderColor: '#8b5cf6',
                                        backgroundColor: 'rgba(139, 92, 246, 0.08)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                    {
                                        label: 'Threat Rate %',
                                        data: trendData.map((p) => p.threat_rate || 0),
                                        borderColor: '#ef4444',
                                        backgroundColor: 'rgba(239, 68, 68, 0.08)',
                                        pointRadius: trendData.length <= 1 ? 3 : 1,
                                        borderWidth: 2,
                                        tension: 0.25,
                                    },
                                ],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                interaction: { mode: 'index', intersect: false },
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8', maxTicksLimit: 8 } },
                                    y: {
                                        min: 0,
                                        max: 100,
                                        grid: { color: 'rgba(255,255,255,0.03)' },
                                        ticks: { color: '#64748b', callback: (v) => `${v}%` },
                                    },
                                },
                                plugins: {
                                    legend: { labels: { color: '#94a3b8', usePointStyle: true, pointStyleWidth: 8 } },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Error */}
            {error && (
                <div className="glass-card p-4 border-red-500/20 flex items-center justify-between">
                    <p className="text-sm text-red-300">{error}</p>
                    <button
                        onClick={() => { setError(null); fetchFlows(); }}
                        className="px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 text-xs font-medium hover:bg-red-500/20 transition-colors"
                    >
                        Retry
                    </button>
                </div>
            )}

            {/* Table */}
            <div className="glass-card overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                    </div>
                ) : flows.length === 0 && !error ? (
                    <div className="flex flex-col items-center justify-center h-64 text-slate-400">
                        <Network size={40} className="mb-3 opacity-50" />
                        <p className="text-sm">No flows to show</p>
                        <p className="text-xs mt-1">Start the backend and load data, or upload a capture.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full data-table">
                            <thead>
                                <tr>
                                    <th><span className="flex items-center gap-1">Time <ArrowUpDown size={10} /></span></th>
                                    <th>Source IP</th>
                                    <th>Dest IP</th>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                    <th>Duration</th>
                                    <th>Bytes/s</th>
                                    <th>Classification</th>
                                    <th>Confidence</th>
                                    <th>Anomaly</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody>
                                {flows.map((flow) => (
                                    <tr key={flow.id}>
                                        <td className="text-xs text-slate-400 whitespace-nowrap">
                                            {new Date(flow.timestamp).toLocaleTimeString()}
                                        </td>
                                        <td className="font-mono text-xs text-cyan-300">{flow.src_ip}</td>
                                        <td className="font-mono text-xs text-slate-300">{flow.dst_ip}</td>
                                        <td className="font-mono text-xs text-slate-400">{flow.dst_port ?? '—'}</td>
                                        <td>
                                            <span className="px-2 py-0.5 rounded-md bg-dark-700 text-xs font-mono text-cyan-400 border border-white/5">
                                                {formatProtocol(flow.protocol)}
                                            </span>
                                        </td>
                                        <td className="text-xs text-slate-400">{flow.duration != null ? `${flow.duration}s` : '—'}</td>
                                        <td className="text-xs text-slate-400 font-mono">
                                            {flow.flow_bytes_per_sec != null ? (flow.flow_bytes_per_sec / 1000).toFixed(1) + 'K' : '—'}
                                        </td>
                                        <td>
                                            <span className={`text-xs font-semibold ${String(flow.classification || '').toLowerCase() === 'benign' ? 'text-green-400' : 'text-red-400'}`}>
                                                {flow.classification}
                                            </span>
                                        </td>
                                        <td>
                                            <div className="flex items-center gap-1.5">
                                                <div className="h-1.5 w-12 rounded-full bg-dark-700 overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full bg-cyan-500"
                                                        style={{ width: `${(flow.confidence ?? 0) * 100}%` }}
                                                    />
                                                </div>
                                                <span className="text-xs text-slate-400">{((flow.confidence ?? 0) * 100).toFixed(0)}%</span>
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`text-xs font-mono ${(flow.anomaly_score ?? 0) > 0.7 ? 'text-red-400' : (flow.anomaly_score ?? 0) > 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                                                {(flow.anomaly_score ?? 0).toFixed(2)}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`px-2 py-0.5 rounded-md text-xs font-medium badge-${(flow.risk_level || 'low').toLowerCase()}`}>
                                                {flow.risk_level ?? '—'}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {flows.length > 0 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-white/5">
                    <p className="text-xs text-slate-400">
                        Showing {((page - 1) * 15) + 1}–{Math.min(page * 15, total)} of {total}
                    </p>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setPage(Math.max(1, page - 1))}
                            disabled={page === 1}
                            className="p-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:border-cyan-500/30 disabled:opacity-30 transition-colors"
                        >
                            <ChevronLeft size={14} />
                        </button>
                        <span className="text-xs text-slate-300 font-medium px-2">
                            {page} / {totalPages}
                        </span>
                        <button
                            onClick={() => setPage(Math.min(totalPages, page + 1))}
                            disabled={page === totalPages}
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
