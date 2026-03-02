import { useState, useEffect, useCallback } from 'react';
import { getDashboardStats } from '../services/api';
import {
    Activity,
    AlertTriangle,
    Shield,
    Zap,
    TrendingUp,
    Globe,
    ArrowUpRight,
    ArrowDownRight,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler } from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler);

const chartColors = ['#00d4ff', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b', '#ef4444', '#06b6d4', '#a855f7'];

export default function Dashboard() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [refreshing, setRefreshing] = useState(false);
    const [lastFetch, setLastFetch] = useState(null);
    const [monitorView, setMonitorView] = useState('passive'); // 'passive' | 'active'

    const fetchStats = useCallback(async () => {
        try {
            setError(null);
            const response = await getDashboardStats(monitorView || undefined);
            const data = response.data;
            setStats(data);
            setLastFetch(new Date().toLocaleTimeString());
            setLoading(false);
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Failed to fetch data');
            setStats(null);
            setLoading(false);
        }
    }, [monitorView]);

    // Fetch on mount and when toggle changes
    useEffect(() => {
        fetchStats();
    }, [fetchStats]);

    // Auto-refresh every 5 seconds (live data for active view)
    useEffect(() => {
        const interval = setInterval(() => {
            fetchStats();
        }, 5000);
        return () => clearInterval(interval);
    }, [fetchStats]);

    const handleManualRefresh = async () => {
        setRefreshing(true);
        await fetchStats();
        setRefreshing(false);
    };

    if (loading && !stats) {
        return <LoadingSkeleton />;
    }

    const statsData = stats || {
        total_flows: 0,
        total_anomalies: 0,
        anomaly_rate: 0,
        avg_risk_score: 0,
        attack_distribution: {},
        risk_distribution: { Critical: 0, High: 0, Medium: 0, Low: 0 },
        timeline: [],
        protocols: {},
    };

    const riskPercent = Math.round((statsData.avg_risk_score || 0) * 100);

    return (
        <div className="space-y-6">
            {/* Toggle: Passive / Active */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">View</span>
                    <div className="flex rounded-xl bg-dark-800 border border-white/5 p-0.5">
                        <button
                            type="button"
                            onClick={() => setMonitorView('passive')}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${monitorView === 'passive'
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                : 'text-slate-400 hover:text-white'}`}
                        >
                            Passive
                        </button>
                        <button
                            type="button"
                            onClick={() => setMonitorView('active')}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${monitorView === 'active'
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                : 'text-slate-400 hover:text-white'}`}
                        >
                            Active
                        </button>
                    </div>
                    <span className="text-xs text-slate-500">
                        {monitorView === 'passive' ? 'File uploads' : 'Live monitoring'}
                    </span>
                </div>
                <div className="flex items-center gap-3">
                    <p className="text-xs text-slate-500">
                        {monitorView === 'active' && (
                            <span className="text-cyan-400 font-medium">Live • </span>
                        )}
                        Last updated: {lastFetch || 'Loading...'} | Total Flows: {statsData.total_flows}
                    </p>
                    <button
                        onClick={handleManualRefresh}
                        disabled={refreshing}
                        className="px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                    >
                        {refreshing ? '⟳ Refreshing...' : '🔄 Refresh'}
                    </button>
                </div>
            </div>

            {/* Header */}
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold gradient-text">Network Dashboard</h1>
            </div>

            {error && (
                <div className="glass-card p-4 border-red-500/20 bg-red-500/5">
                    <p className="text-red-400 text-sm">⚠️ {error}</p>
                </div>
            )}

            {statsData.total_flows === 0 && !error && (
                <div className="glass-card p-8 text-center border-yellow-500/20 bg-yellow-500/5">
                    <p className="text-yellow-300 mb-2">📤 No data yet</p>
                    <p className="text-sm text-slate-400">
                        {monitorView === 'passive'
                            ? 'Upload a network file on the Upload page to see analysis results here.'
                            : 'Start Active Monitoring (use Default/lo), then use the app to generate traffic. Backend must run with sudo.'}
                    </p>
                </div>
            )}

            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <KPICard
                    title="Total Flows"
                    value={statsData.total_flows.toLocaleString()}
                    icon={Activity}
                    color="cyan"
                    trend="+12.5%"
                    trendUp={true}
                />
                <KPICard
                    title="Anomalies Detected"
                    value={statsData.total_anomalies.toLocaleString()}
                    icon={AlertTriangle}
                    color="red"
                    trend={`${statsData.anomaly_rate}%`}
                    trendUp={false}
                    subtitle="Anomaly Rate"
                />
                <KPICard
                    title="Avg Risk Score"
                    value={riskPercent + '%'}
                    icon={Shield}
                    color="purple"
                    trend={riskPercent > 50 ? 'High' : 'Normal'}
                    trendUp={riskPercent > 50}
                />
                <KPICard
                    title="Active Protocols"
                    value={Object.keys(statsData.protocols || {}).length}
                    icon={Globe}
                    color="green"
                    trend="Live"
                    trendUp={true}
                />
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Attack Distribution Doughnut */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                        <Zap size={14} className="text-cyan-400" />
                        Attack Distribution
                    </h3>
                    <div className="h-56 flex items-center justify-center">
                        <Doughnut
                            data={{
                                labels: Object.keys(statsData.attack_distribution || {}),
                                datasets: [{
                                    data: Object.values(statsData.attack_distribution || {}),
                                    backgroundColor: chartColors,
                                    borderWidth: 0,
                                    spacing: 2,
                                    borderRadius: 4,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                cutout: '65%',
                                plugins: {
                                    legend: {
                                        position: 'right',
                                        labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' }, padding: 8, usePointStyle: true, pointStyleWidth: 8 },
                                    },
                                },
                            }}
                        />
                    </div>
                </div>

                {/* Timeline Line Chart */}
                <div className="glass-card p-5 lg:col-span-2">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                        <TrendingUp size={14} className="text-cyan-400" />
                        Traffic Timeline (24h)
                    </h3>
                    <div className="h-56">
                        <Line
                            data={{
                                labels: (statsData.timeline || []).map(t => t.hour),
                                datasets: [
                                    {
                                        label: 'Total Flows',
                                        data: (statsData.timeline || []).map(t => t.total),
                                        borderColor: '#00d4ff',
                                        backgroundColor: 'rgba(0, 212, 255, 0.08)',
                                        fill: true,
                                        tension: 0.4,
                                        pointRadius: 0,
                                        pointHoverRadius: 4,
                                        borderWidth: 2,
                                    },
                                    {
                                        label: 'Anomalies',
                                        data: (statsData.timeline || []).map(t => t.anomalies),
                                        borderColor: '#ef4444',
                                        backgroundColor: 'rgba(239, 68, 68, 0.08)',
                                        fill: true,
                                        tension: 0.4,
                                        pointRadius: 0,
                                        pointHoverRadius: 4,
                                        borderWidth: 2,
                                    },
                                ],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 10 } } },
                                    y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 10 } } },
                                },
                                plugins: {
                                    legend: { labels: { color: '#94a3b8', font: { size: 11 }, usePointStyle: true, pointStyleWidth: 8 } },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Bottom Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Risk Distribution */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                        <Shield size={14} className="text-purple-400" />
                        Risk Distribution
                    </h3>
                    <div className="space-y-3 mt-2">
                        {Object.entries(statsData.risk_distribution || {}).map(([level, count]) => {
                            const total = statsData.total_flows || 1;
                            const pct = Math.round((count / total) * 100);
                            const colorMap = {
                                Critical: { bg: 'bg-red-500', text: 'text-red-400' },
                                High: { bg: 'bg-orange-500', text: 'text-orange-400' },
                                Medium: { bg: 'bg-purple-500', text: 'text-purple-400' },
                                Low: { bg: 'bg-green-500', text: 'text-green-400' },
                            };
                            const c = colorMap[level] || { bg: 'bg-slate-500', text: 'text-slate-400' };
                            return (
                                <div key={level}>
                                    <div className="flex justify-between text-xs mb-1">
                                        <span className={`font-medium ${c.text}`}>{level}</span>
                                        <span className="text-slate-400">{count} ({pct}%)</span>
                                    </div>
                                    <div className="h-2 rounded-full bg-dark-700 overflow-hidden">
                                        <div
                                            className={`h-full rounded-full ${c.bg} transition-all duration-1000`}
                                            style={{ width: `${pct}%` }}
                                        />
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Risk Score Gauge */}
                    <div className="mt-6 flex items-center justify-center">
                        <div className="relative w-32 h-32">
                            <svg viewBox="0 0 100 100" className="transform -rotate-90">
                                <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
                                <circle
                                    cx="50" cy="50" r="40" fill="none"
                                    stroke={riskPercent > 70 ? '#ef4444' : riskPercent > 40 ? '#f59e0b' : '#10b981'}
                                    strokeWidth="8"
                                    strokeLinecap="round"
                                    strokeDasharray={`${riskPercent * 2.51} 251`}
                                    className="transition-all duration-1000"
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                <span className="text-2xl font-bold text-white">{riskPercent}</span>
                                <span className="text-[10px] text-slate-400">Risk Score</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Protocol Distribution Bar */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                        <Globe size={14} className="text-green-400" />
                        Protocol Distribution
                    </h3>
                    <div className="h-72">
                        <Bar
                            data={{
                                labels: Object.keys(statsData.protocols || {}),
                                datasets: [{
                                    label: 'Flows',
                                    data: Object.values(statsData.protocols || {}),
                                    backgroundColor: chartColors.map(c => c + '40'),
                                    borderColor: chartColors,
                                    borderWidth: 1,
                                    borderRadius: 6,
                                }],
                            }}
                            options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                indexAxis: 'y',
                                scales: {
                                    x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#64748b', font: { size: 10 } } },
                                    y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11, family: 'JetBrains Mono' } } },
                                },
                                plugins: {
                                    legend: { display: false },
                                },
                            }}
                        />
                    </div>
                </div>
            </div>

            {/* Top Source IPs Table */}
            <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                    <Globe size={14} className="text-cyan-400" />
                    Top Source IPs
                </h3>
                <div className="overflow-x-auto">
                    <table className="w-full data-table">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>IP Address</th>
                                <th>Flow Count</th>
                                <th>Traffic Share</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(statsData.top_sources || []).map((ip, i) => (
                                <tr key={ip.ip}>
                                    <td className="font-mono text-cyan-400">#{i + 1}</td>
                                    <td className="font-mono text-slate-200">{ip.ip}</td>
                                    <td>{ip.count}</td>
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <div className="h-1.5 rounded-full bg-dark-700 w-20 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-cyan-500"
                                                    style={{ width: `${Math.round((ip.count / Math.max(1, statsData.total_flows || 0)) * 100)}%` }}
                                                />
                                            </div>
                                            <span className="text-xs text-slate-400">
                                                {Math.round((ip.count / Math.max(1, statsData.total_flows || 0)) * 100)}%
                                            </span>
                                        </div>
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

function KPICard({ title, value, icon: Icon, color, trend, trendUp, subtitle }) {
    const colorMap = {
        cyan: { bg: 'from-cyan-500/10 to-cyan-500/5', icon: 'text-cyan-400', border: 'border-cyan-500/20' },
        red: { bg: 'from-red-500/10 to-red-500/5', icon: 'text-red-400', border: 'border-red-500/20' },
        purple: { bg: 'from-purple-500/10 to-purple-500/5', icon: 'text-purple-400', border: 'border-purple-500/20' },
        green: { bg: 'from-green-500/10 to-green-500/5', icon: 'text-green-400', border: 'border-green-500/20' },
    };
    const c = colorMap[color];

    return (
        <div className={`glass-card p-4 bg-gradient-to-br ${c.bg} border ${c.border} animate-slide-up`}>
            <div className="flex items-start justify-between">
                <div>
                    <p className="text-xs text-slate-400 font-medium mb-1">{title}</p>
                    <p className="text-2xl font-bold text-white">{value}</p>
                </div>
                <div className={`p-2 rounded-xl bg-dark-800/50 ${c.icon}`}>
                    <Icon size={18} />
                </div>
            </div>
            <div className="flex items-center gap-1 mt-2">
                {trendUp ? (
                    <ArrowUpRight size={12} className="text-green-400" />
                ) : (
                    <ArrowDownRight size={12} className="text-red-400" />
                )}
                <span className={`text-xs font-medium ${trendUp ? 'text-green-400' : 'text-red-400'}`}>{trend}</span>
                {subtitle && <span className="text-xs text-slate-500 ml-1">{subtitle}</span>}
            </div>
        </div>
    );
}

function LoadingSkeleton() {
    return (
        <div className="space-y-6 animate-pulse">
            <div className="grid grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => (
                    <div key={i} className="glass-card h-28 rounded-2xl" />
                ))}
            </div>
            <div className="grid grid-cols-3 gap-4">
                <div className="glass-card h-72 rounded-2xl" />
                <div className="glass-card h-72 rounded-2xl col-span-2" />
            </div>
        </div>
    );
}

function ErrorState({ onRetry }) {
    return (
        <div className="flex flex-col items-center justify-center h-96">
            <AlertTriangle size={48} className="text-red-400 mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Failed to Load Dashboard</h3>
            <p className="text-sm text-slate-400 mb-4">Start the backend API to see live stats, or retry if it just came online.</p>
            {onRetry && (
                <button
                    onClick={onRetry}
                    className="px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-sm font-medium hover:bg-cyan-500/30 transition-colors"
                >
                    Retry
                </button>
            )}
        </div>
    );
}
