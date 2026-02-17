import { useState, useEffect } from 'react';
import { getTrafficFlows } from '../services/api';
import {
    Network,
    Search,
    ChevronLeft,
    ChevronRight,
    Filter,
    ArrowUpDown,
} from 'lucide-react';

export default function TrafficAnalysis() {
    const [flows, setFlows] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [loading, setLoading] = useState(true);
    const [filters, setFilters] = useState({
        classification: '',
        risk_level: '',
        src_ip: '',
        protocol: '',
    });

    useEffect(() => {
        fetchFlows();
    }, [page, filters]);

    const fetchFlows = async () => {
        setLoading(true);
        try {
            const params = { page, per_page: 15 };
            if (filters.classification) params.classification = filters.classification;
            if (filters.risk_level) params.risk_level = filters.risk_level;
            if (filters.src_ip) params.src_ip = filters.src_ip;
            if (filters.protocol) params.protocol = filters.protocol;

            const { data } = await getTrafficFlows(params);
            setFlows(data.flows);
            setTotal(data.total);
            setTotalPages(data.total_pages);
        } catch (err) {
            console.error('Failed to fetch flows:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleFilterChange = (key, value) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
        setPage(1);
    };

    const clearFilters = () => {
        setFilters({ classification: '', risk_level: '', src_ip: '', protocol: '' });
        setPage(1);
    };

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
                        {['Benign', 'DDoS', 'PortScan', 'BruteForce', 'Web Attack', 'Bot', 'Infiltration', 'Heartbleed'].map((c) => (
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
                        {['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH'].map((p) => (
                            <option key={p} value={p}>{p}</option>
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

            {/* Table */}
            <div className="glass-card overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
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
                                        <td className="font-mono text-xs text-slate-400">{flow.dst_port}</td>
                                        <td>
                                            <span className="px-2 py-0.5 rounded-md bg-dark-700 text-xs font-mono text-cyan-400 border border-white/5">
                                                {flow.protocol}
                                            </span>
                                        </td>
                                        <td className="text-xs text-slate-400">{flow.duration}s</td>
                                        <td className="text-xs text-slate-400 font-mono">{(flow.flow_bytes_per_sec / 1000).toFixed(1)}K</td>
                                        <td>
                                            <span className={`text-xs font-semibold ${flow.classification === 'Benign' ? 'text-green-400' : 'text-red-400'}`}>
                                                {flow.classification}
                                            </span>
                                        </td>
                                        <td>
                                            <div className="flex items-center gap-1.5">
                                                <div className="h-1.5 w-12 rounded-full bg-dark-700 overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full bg-cyan-500"
                                                        style={{ width: `${flow.confidence * 100}%` }}
                                                    />
                                                </div>
                                                <span className="text-xs text-slate-400">{(flow.confidence * 100).toFixed(0)}%</span>
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`text-xs font-mono ${flow.anomaly_score > 0.7 ? 'text-red-400' : flow.anomaly_score > 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                                                {flow.anomaly_score.toFixed(2)}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`px-2 py-0.5 rounded-md text-xs font-medium badge-${flow.risk_level.toLowerCase()}`}>
                                                {flow.risk_level}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
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
            </div>
        </div>
    );
}
