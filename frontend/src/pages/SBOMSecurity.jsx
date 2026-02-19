import { useState, useEffect } from 'react';
import { getSBOM, getVulnerabilities, downloadSBOM } from '../services/api';
import {
    Shield,
    Download,
    AlertTriangle,
    Package,
    Bug,
    CheckCircle2,
    ExternalLink,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

export default function SBOMSecurity() {
    const [sbom, setSbom] = useState(null);
    const [vulns, setVulns] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState({ sbom: null, vulns: null });
    const [activeTab, setActiveTab] = useState('overview');

    const fetchSecurity = async () => {
        setLoading(true);
        setError({ sbom: null, vulns: null });
        try {
            const [sbomResult, vulnResult] = await Promise.allSettled([getSBOM(), getVulnerabilities()]);
            if (sbomResult.status === 'fulfilled') setSbom(sbomResult.value.data);
            else setError((e) => ({ ...e, sbom: sbomResult.reason?.message || 'SBOM unavailable' }));
            if (vulnResult.status === 'fulfilled') setVulns(vulnResult.value.data);
            else setError((e) => ({ ...e, vulns: vulnResult.reason?.message || 'Vulnerabilities unavailable' }));
        } catch (err) {
            console.error('Failed to fetch security data:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSecurity();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    const severityColors = {
        Critical: { bg: '#ef444440', border: '#ef4444', text: 'text-red-400', badge: 'badge-critical' },
        High: { bg: '#f59e0b40', border: '#f59e0b', text: 'text-orange-400', badge: 'badge-high' },
        Medium: { bg: '#8b5cf640', border: '#8b5cf6', text: 'text-purple-400', badge: 'badge-medium' },
        Low: { bg: '#10b98140', border: '#10b981', text: 'text-green-400', badge: 'badge-low' },
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-xl font-bold text-white flex items-center gap-2">
                        <Shield size={20} className="text-cyan-400" />
                        SBOM Security
                    </h1>
                    <p className="text-xs text-slate-400 mt-1">
                        Software Bill of Materials and vulnerability analysis
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    {(error.sbom || error.vulns) && (
                        <button
                            onClick={fetchSecurity}
                            className="px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-xs font-medium hover:bg-cyan-500/20 transition-colors"
                        >
                            Retry
                        </button>
                    )}
                <a
                    href={downloadSBOM()}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-sm font-semibold hover:opacity-90 transition-opacity flex items-center gap-2"
                >
                    <Download size={14} />
                    Download SBOM
                </a>
                </div>
            </div>

            {(error.sbom || error.vulns) && (
                <div className="glass-card p-3 border-amber-500/20 flex items-center gap-3">
                    <AlertTriangle size={18} className="text-amber-400 shrink-0" />
                    <div className="text-sm text-slate-300">
                        {error.sbom && <span>SBOM: {error.sbom}. </span>}
                        {error.vulns && <span>Vulnerabilities: {error.vulns}. </span>}
                        Start the backend or add security/sbom.json for full data.
                    </div>
                </div>
            )}

            {/* KPIs */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="glass-card p-4 bg-gradient-to-br from-cyan-500/10 to-cyan-500/5 border border-cyan-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <Package size={18} className="text-cyan-400" />
                        <div>
                            <p className="text-xs text-slate-400">Components</p>
                            <p className="text-2xl font-bold text-white">{sbom?.total_components || 0}</p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-4 bg-gradient-to-br from-red-500/10 to-red-500/5 border border-red-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <Bug size={18} className="text-red-400" />
                        <div>
                            <p className="text-xs text-slate-400">Vulnerabilities</p>
                            <p className="text-2xl font-bold text-white">{vulns?.total_vulnerabilities || 0}</p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-4 bg-gradient-to-br from-orange-500/10 to-orange-500/5 border border-orange-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <AlertTriangle size={18} className="text-orange-400" />
                        <div>
                            <p className="text-xs text-slate-400">Critical/High</p>
                            <p className="text-2xl font-bold text-white">
                                {(vulns?.severity_distribution?.Critical || 0) + (vulns?.severity_distribution?.High || 0)}
                            </p>
                        </div>
                    </div>
                </div>
                <div className="glass-card p-4 bg-gradient-to-br from-green-500/10 to-green-500/5 border border-green-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <CheckCircle2 size={18} className="text-green-400" />
                        <div>
                            <p className="text-xs text-slate-400">Format</p>
                            <p className="text-lg font-bold text-white">{sbom?.format || 'CycloneDX'}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-2 border-b border-white/5 pb-0">
                {['overview', 'components', 'vulnerabilities'].map((tab) => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${activeTab === tab
                                ? 'text-cyan-400 border-cyan-400'
                                : 'text-slate-400 border-transparent hover:text-white'
                            }`}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            {activeTab === 'overview' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-fade-in">
                    {/* Severity Distribution */}
                    <div className="glass-card p-5">
                        <h3 className="text-sm font-semibold text-slate-300 mb-4">Vulnerability Severity</h3>
                        <div className="h-64 flex items-center justify-center">
                            <Doughnut
                                data={{
                                    labels: Object.keys(vulns?.severity_distribution || {}),
                                    datasets: [{
                                        data: Object.values(vulns?.severity_distribution || {}),
                                        backgroundColor: ['#ef444440', '#f59e0b40', '#8b5cf640', '#10b98140'],
                                        borderColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#10b981'],
                                        borderWidth: 1,
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

                    {/* Severity Bars */}
                    <div className="glass-card p-5">
                        <h3 className="text-sm font-semibold text-slate-300 mb-4">Severity Breakdown</h3>
                        <div className="space-y-4 mt-4">
                            {Object.entries(vulns?.severity_distribution || {}).map(([sev, count]) => {
                                const total = vulns?.total_vulnerabilities || 1;
                                const pct = Math.round((count / total) * 100);
                                const sc = severityColors[sev];
                                return (
                                    <div key={sev}>
                                        <div className="flex justify-between text-xs mb-1.5">
                                            <span className={`font-medium ${sc?.text}`}>{sev}</span>
                                            <span className="text-slate-400">{count} ({pct}%)</span>
                                        </div>
                                        <div className="h-3 rounded-full bg-dark-700 overflow-hidden">
                                            <div
                                                className="h-full rounded-full transition-all duration-1000"
                                                style={{ width: `${pct}%`, backgroundColor: sc?.border }}
                                            />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                        <div className="mt-6 p-3 rounded-xl bg-dark-800/50 border border-white/5">
                            <p className="text-xs text-slate-400 mb-1">Scanner</p>
                            <p className="text-sm font-medium text-white">{vulns?.scanner || 'Grype'}</p>
                            <p className="text-xs text-slate-400 mt-2 mb-1">Last Scan</p>
                            <p className="text-sm font-medium text-white">
                                {vulns?.scan_timestamp ? new Date(vulns.scan_timestamp).toLocaleString() : 'N/A'}
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {activeTab === 'components' && (
                <div className="glass-card overflow-hidden animate-fade-in">
                    <div className="overflow-x-auto">
                        <table className="w-full data-table">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Package Name</th>
                                    <th>Version</th>
                                    <th>Type</th>
                                    <th>PURL</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(sbom?.components || []).map((comp, i) => (
                                    <tr key={i}>
                                        <td className="font-mono text-xs text-cyan-400">#{i + 1}</td>
                                        <td className="font-medium text-white text-sm">{comp.name}</td>
                                        <td>
                                            <span className="px-2 py-0.5 rounded-md bg-dark-700 text-xs font-mono text-cyan-400 border border-white/5">
                                                {comp.version}
                                            </span>
                                        </td>
                                        <td className="text-xs text-slate-400 capitalize">{comp.type}</td>
                                        <td className="text-xs text-slate-500 font-mono max-w-xs truncate">{comp.purl || '—'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {activeTab === 'vulnerabilities' && (
                <div className="space-y-3 animate-fade-in">
                    {(vulns?.vulnerabilities || []).map((v) => {
                        const sc = severityColors[v.severity];
                        return (
                            <div key={v.id} className={`glass-card p-4 border ${sc?.badge === 'badge-critical' ? 'border-red-500/20' : 'border-white/5'}`}>
                                <div className="flex items-start justify-between">
                                    <div className="flex items-start gap-3">
                                        <Bug size={18} className={sc?.text} />
                                        <div>
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="text-sm font-bold text-white font-mono">{v.id}</span>
                                                <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${sc?.badge}`}>
                                                    {v.severity}
                                                </span>
                                            </div>
                                            <p className="text-sm text-slate-300 mb-2">{v.description}</p>
                                            <div className="flex items-center gap-4 text-xs text-slate-400">
                                                <span>
                                                    <span className="text-slate-500">Package:</span>{' '}
                                                    <span className="font-mono text-white">{v.package} v{v.version}</span>
                                                </span>
                                                <span>
                                                    <span className="text-slate-500">Fixed in:</span>{' '}
                                                    <span className="font-mono text-green-400">v{v.fixed_in}</span>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <a
                                        href={`https://nvd.nist.gov/vuln/detail/${v.id}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="p-1.5 rounded-lg hover:bg-white/5 text-slate-400 hover:text-cyan-400 transition-colors"
                                    >
                                        <ExternalLink size={14} />
                                    </a>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
