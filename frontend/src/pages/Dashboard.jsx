import { useState, useEffect } from 'react';
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

    const fetchStats = async () => {
        setLoading(true);
        try {
            const { data } = await getDashboardStats();
            setStats(data);
        } catch (err) {
            console.error('Failed to fetch dashboard stats:', err);
            setStats(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStats();
    }, []);

    if (loading) return <LoadingSkeleton />;
    if (!stats) return <ErrorState onRetry={fetchStats} />;

    const riskPercent = Math.round(stats.avg_risk_score * 100);

    return (
        <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <KPICard
                    title="Total Flows"
                    value={stats.total_flows.toLocaleString()}
                    icon={Activity}
                    color="cyan"
                    trend="+12.5%"
                    trendUp={true}
                />
                <KPICard
                    title="Anomalies Detected"
                    value={stats.total_anomalies.toLocaleString()}
                    icon={AlertTriangle}
                    color="red"
                    trend={`${stats.anomaly_rate}%`}
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
                    value={Object.keys(stats.protocols || {}).length}
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
                                labels: Object.keys(stats.attack_distribution),
                                datasets: [{
                                    data: Object.values(stats.attack_distribution),
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
                                labels: (stats.timeline || []).map(t => t.hour),
                                datasets: [
                                    {
                                        label: 'Total Flows',
                                        data: (stats.timeline || []).map(t => t.total),
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
                                        data: (stats.timeline || []).map(t => t.anomalies),
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
                        {Object.entries(stats.risk_distribution || {}).map(([level, count]) => {
                            const total = stats.total_flows || 1;
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
                                labels: Object.keys(stats.protocols || {}),
                                datasets: [{
                                    label: 'Flows',
                                    data: Object.values(stats.protocols || {}),
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
                            {(stats.top_sources || []).map((ip, i) => (
                                <tr key={ip.ip}>
                                    <td className="font-mono text-cyan-400">#{i + 1}</td>
                                    <td className="font-mono text-slate-200">{ip.ip}</td>
                                    <td>{ip.count}</td>
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <div className="h-1.5 rounded-full bg-dark-700 w-20 overflow-hidden">
                                                <div
                                                    className="h-full rounded-full bg-cyan-500"
                                                    style={{ width: `${Math.round((ip.count / stats.total_flows) * 100)}%` }}
                                                />
                                            </div>
                                            <span className="text-xs text-slate-400">
                                                {Math.round((ip.count / stats.total_flows) * 100)}%
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
