import { useState, useEffect } from 'react';
import { getSBOM, getVulnerabilities, analyzeSBOMFile, downloadSBOM } from '../services/api';
import {
    Shield,
    Download,
    AlertTriangle,
    Package,
    Bug,
    CheckCircle2,
    ExternalLink,
    FileUp,
    Loader2,
    Lightbulb,
    ChevronDown,
    ChevronUp,
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const ALLOWED_FILES = ['.txt', '.json', 'package-lock.json', 'yarn.lock', 'Pipfile', 'poetry.lock', 'Gemfile', 'Gemfile.lock', 'go.mod', 'Cargo.toml', 'Cargo.lock'];

export default function SBOMSecurity() {
    const [sbom, setSbom] = useState(null);
    const [vulns, setVulns] = useState(null);
    const [loading, setLoading] = useState(true);
    const [analyzing, setAnalyzing] = useState(false);
    const [error, setError] = useState({ sbom: null, vulns: null });
    const [activeTab, setActiveTab] = useState('overview');
    const [selectedSeverityFilter, setSelectedSeverityFilter] = useState('');
    const [hoveredSeverity, setHoveredSeverity] = useState('');
    const [file, setFile] = useState(null);
    const [expandedTips, setExpandedTips] = useState({});

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

    const hasUserData = !!vulns?.scanner || (sbom?.total_components ?? 0) > 0;

    const handleFileSelect = (e) => {
        const f = e.target.files?.[0];
        if (f) {
            setFile(f);
            setError({ sbom: null, vulns: null });
        }
    };

    const handleAnalyze = async () => {
        if (!file) return;
        setAnalyzing(true);
        setError({ sbom: null, vulns: null });
        try {
            const { data } = await analyzeSBOMFile(file);
            setSbom({
                total_components: data.total_components,
                components: data.components,
                format: 'CycloneDX',
                metadata: { timestamp: data.scan_timestamp, component: { name: data.filename } },
            });
            setVulns({
                total_vulnerabilities: data.total_vulnerabilities,
                severity_distribution: data.severity_distribution || {},
                vulnerabilities: data.vulnerabilities || [],
                scan_timestamp: data.scan_timestamp,
                scanner: data.scanner || 'CycloneDX',
                warnings: data.warnings || [],
            });
        } catch (err) {
            setError({ sbom: err.response?.data?.detail || 'Analysis failed', vulns: null });
        } finally {
            setAnalyzing(false);
        }
    };

    const toggleTips = (id) => {
        setExpandedTips((p) => ({ ...p, [id]: !p[id] }));
    };

    const severityColors = {
        Critical: { bg: '#ef444440', border: '#ef4444', text: 'text-red-400', badge: 'badge-critical' },
        High: { bg: '#f59e0b40', border: '#f59e0b', text: 'text-orange-400', badge: 'badge-high' },
        Medium: { bg: '#8b5cf640', border: '#8b5cf6', text: 'text-purple-400', badge: 'badge-medium' },
        Low: { bg: '#10b98140', border: '#10b981', text: 'text-green-400', badge: 'badge-low' },
        Unknown: { bg: '#64748b40', border: '#64748b', text: 'text-slate-400', badge: 'badge-unknown' },
    };
    const allVulns = vulns?.vulnerabilities || [];
    const severityToVulnNames = allVulns.reduce((acc, v) => {
        const sev = v?.severity || 'Unknown';
        if (!acc[sev]) acc[sev] = [];
        acc[sev].push(v?.id || v?.package || 'Unknown');
        return acc;
    }, {});
    const hoveredNames = hoveredSeverity ? (severityToVulnNames[hoveredSeverity] || []) : [];
    const filteredVulns = allVulns.filter((v) => {
        if (!selectedSeverityFilter) return true;
        if (selectedSeverityFilter === 'Critical/High') return v?.severity === 'Critical' || v?.severity === 'High';
        return v?.severity === selectedSeverityFilter;
    });
    const metadata = sbom?.metadata || {};
    const metadataComponent = metadata?.component || {};
    const metadataTools = metadata?.tools || [];

    return (
        <div className="space-y-6">
            {/* Header + Upload */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                    <h1 className="text-xl font-bold text-white flex items-center gap-2">
                        <Shield size={20} className="text-cyan-400" />
                        SBOM Security
                    </h1>
                    <p className="text-xs text-slate-400 mt-1">
                        Upload your dependency file to analyze components and vulnerabilities
                    </p>
                </div>
                {hasUserData && (
                    <a
                        href={downloadSBOM()}
                        download="sbom.json"
                        className="px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 flex items-center gap-2 text-sm font-medium"
                    >
                        <Download size={16} />
                        Download SBOM
                    </a>
                )}
            </div>

            {/* Upload Zone */}
            <div
                className="glass-card p-6 border-2 border-dashed border-cyan-500/30 hover:border-cyan-400/50 transition-colors"
                onClick={() => document.getElementById('sbom-file-input').click()}
            >
                <input
                    id="sbom-file-input"
                    type="file"
                    accept=".txt,.json,Pipfile,poetry.lock,Gemfile,Gemfile.lock,go.mod,Cargo.toml,Cargo.lock,yarn.lock"
                    onChange={handleFileSelect}
                    className="hidden"
                />
                <div className="flex flex-col sm:flex-row items-center gap-4">
                    <div className="p-3 rounded-xl bg-cyan-500/10">
                        <FileUp size={24} className="text-cyan-400" />
                    </div>
                    <div className="flex-1 text-center sm:text-left">
                        <p className="text-sm font-medium text-white">
                            {file ? file.name : 'Upload dependencies file'}
                        </p>
                        <p className="text-xs text-slate-400 mt-1">
                            {ALLOWED_FILES.join(', ')}
                        </p>
                    </div>
                    <button
                        onClick={(e) => { e.stopPropagation(); handleAnalyze(); }}
                        disabled={!file || analyzing}
                        className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-sm font-semibold hover:opacity-90 disabled:opacity-50 flex items-center gap-2"
                    >
                        {analyzing ? (
                            <>
                                <Loader2 size={14} className="animate-spin" />
                                Analyzing...
                            </>
                        ) : (
                            <>
                                <Shield size={14} />
                                Analyze
                            </>
                        )}
                    </button>
                </div>
            </div>

            {(error.sbom || error.vulns) && (
                <div className="glass-card p-3 border-amber-500/20 flex items-center gap-3">
                    <AlertTriangle size={18} className="text-amber-400 shrink-0" />
                    <div className="text-sm text-slate-300">
                        {error.sbom && <span>{error.sbom}. </span>}
                        {error.vulns && <span>Vulnerabilities: {error.vulns}. </span>}
                    </div>
                    <button
                        onClick={fetchSecurity}
                        className="px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-xs font-medium hover:bg-cyan-500/20"
                    >
                        Retry
                    </button>
                </div>
            )}

            {vulns?.warnings?.length > 0 && (
                <div className="glass-card p-3 border-cyan-500/20 flex items-start gap-3">
                    <AlertTriangle size={18} className="text-cyan-400 shrink-0 mt-0.5" />
                    <div className="text-sm text-slate-300">
                        {vulns.warnings.map((w, i) => (
                            <p key={i}>{w}</p>
                        ))}
                    </div>
                </div>
            )}

            {loading && !sbom && !vulns ? (
                <div className="flex items-center justify-center h-96">
                    <Loader2 size={32} className="animate-spin text-cyan-400" />
                </div>
            ) : !hasUserData ? (
                <div className="glass-card p-12 text-center">
                    <div className="inline-flex p-4 rounded-2xl bg-cyan-500/10 mb-4">
                        <Shield size={48} className="text-cyan-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-white mb-2">Analyze Your Dependencies</h3>
                    <p className="text-sm text-slate-400 max-w-md mx-auto mb-6">
                        Upload a dependency file (requirements.txt, package.json, package-lock.json, yarn.lock, Pipfile, poetry.lock, Gemfile, Gemfile.lock, go.mod, Cargo.toml, or Cargo.lock) to see your SBOM components and vulnerability report with remediation tips.
                    </p>
                    <p className="text-xs text-slate-500">Select a file above and click Analyze to get started.</p>
                </div>
            ) : (
                <>
                    {/* KPIs */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <button
                            type="button"
                            onClick={() => { setActiveTab('components'); setSelectedSeverityFilter(''); }}
                            className="glass-card p-4 bg-gradient-to-br from-cyan-500/10 to-cyan-500/5 border border-cyan-500/20 text-left hover:border-cyan-400/40 transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <Package size={18} className="text-cyan-400" />
                                <div>
                                    <p className="text-xs text-slate-400">Components</p>
                                    <p className="text-2xl font-bold text-white">{sbom?.total_components || 0}</p>
                                </div>
                            </div>
                        </button>
                        <button
                            type="button"
                            onClick={() => { setActiveTab('vulnerabilities'); setSelectedSeverityFilter(''); }}
                            className="glass-card p-4 bg-gradient-to-br from-red-500/10 to-red-500/5 border border-red-500/20 text-left hover:border-red-400/40 transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <Bug size={18} className="text-red-400" />
                                <div>
                                    <p className="text-xs text-slate-400">Vulnerabilities</p>
                                    <p className="text-2xl font-bold text-white">{vulns?.total_vulnerabilities || 0}</p>
                                </div>
                            </div>
                        </button>
                        <button
                            type="button"
                            onClick={() => { setActiveTab('vulnerabilities'); setSelectedSeverityFilter('Critical/High'); }}
                            className="glass-card p-4 bg-gradient-to-br from-orange-500/10 to-orange-500/5 border border-orange-500/20 text-left hover:border-orange-400/40 transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <AlertTriangle size={18} className="text-orange-400" />
                                <div>
                                    <p className="text-xs text-slate-400">Critical/High</p>
                                    <p className="text-2xl font-bold text-white">
                                        {(vulns?.severity_distribution?.Critical || 0) + (vulns?.severity_distribution?.High || 0)}
                                    </p>
                                </div>
                            </div>
                        </button>
                        <div className="glass-card p-4 bg-gradient-to-br from-green-500/10 to-green-500/5 border border-green-500/20">
                            <div className="flex items-center gap-3">
                                <CheckCircle2 size={18} className="text-green-400" />
                                <div>
                                    <p className="text-xs text-slate-400">Scanner</p>
                                    <p className="text-lg font-bold text-white">{vulns?.scanner || 'OSV'}</p>
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
                                className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${activeTab === tab ? 'text-cyan-400 border-cyan-400' : 'text-slate-400 border-transparent hover:text-white'}`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>

                    {/* Overview */}
                    {activeTab === 'overview' && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-fade-in">
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
                                            onHover: (event, elements) => {
                                                if (elements?.length) {
                                                    const idx = elements[0].index;
                                                    setHoveredSeverity(Object.keys(vulns?.severity_distribution || {})[idx] || '');
                                                } else setHoveredSeverity('');
                                            },
                                            onClick: (_, elements) => {
                                                if (elements?.length) {
                                                    const sev = Object.keys(vulns?.severity_distribution || {})[elements[0].index];
                                                    setActiveTab('vulnerabilities');
                                                    setSelectedSeverityFilter(sev);
                                                }
                                            },
                                            plugins: { legend: { position: 'right' } },
                                        }}
                                    />
                                </div>
                            </div>
                            <div className="glass-card p-5">
                                <h3 className="text-sm font-semibold text-slate-300 mb-4">Severity Breakdown</h3>
                                <div className="space-y-4 mt-4">
                                    {Object.entries(vulns?.severity_distribution || {}).map(([sev, count]) => {
                                        const total = vulns?.total_vulnerabilities || 1;
                                        const pct = Math.round((count / total) * 100);
                                        const sc = severityColors[sev];
                                        return (
                                            <button
                                                key={sev}
                                                type="button"
                                                onClick={() => { setActiveTab('vulnerabilities'); setSelectedSeverityFilter(sev); }}
                                                className="w-full text-left group"
                                            >
                                                <div className="flex justify-between text-xs mb-1.5">
                                                    <span className={`font-medium ${sc?.text}`}>{sev}</span>
                                                    <span className="text-slate-400">{count} ({pct}%)</span>
                                                </div>
                                                <div className="h-3 rounded-full bg-dark-700 overflow-hidden">
                                                    <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: sc?.border }} />
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>
                                <div className="mt-6 p-3 rounded-xl bg-dark-800/50 border border-white/5">
                                    <p className="text-xs text-slate-400 mb-1">Scanner</p>
                                    <p className="text-sm font-medium text-white">{vulns?.scanner || 'OSV'}</p>
                                    <p className="text-xs text-slate-400 mt-2 mb-1">Last Scan</p>
                                    <p className="text-sm font-medium text-white">
                                        {vulns?.scan_timestamp ? new Date(vulns.scan_timestamp).toLocaleString() : 'N/A'}
                                    </p>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Components */}
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
                                                    <span className="px-2 py-0.5 rounded-md bg-dark-700 text-xs font-mono text-cyan-400">{comp.version}</span>
                                                </td>
                                                <td className="text-xs text-slate-400 capitalize">{comp.type || 'library'}</td>
                                                <td className="text-xs text-slate-500 font-mono max-w-xs truncate">{comp.purl || '—'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Vulnerabilities with Tips */}
                    {activeTab === 'vulnerabilities' && (
                        <div className="space-y-3 animate-fade-in">
                            <div className="flex items-center justify-between">
                                <p className="text-xs text-slate-400">
                                    Showing {filteredVulns.length} vulnerabilities
                                    {selectedSeverityFilter ? ` (${selectedSeverityFilter})` : ''}
                                </p>
                                {selectedSeverityFilter && (
                                    <button
                                        type="button"
                                        onClick={() => setSelectedSeverityFilter('')}
                                        className="px-2 py-1 rounded-md text-xs text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10"
                                    >
                                        Clear Filter
                                    </button>
                                )}
                            </div>
                            {filteredVulns.map((v) => {
                                const sc = severityColors[v.severity];
                                const isExpanded = expandedTips[v.id];
                                const tips = v.tips || [];
                                return (
                                    <div
                                        key={`${v.id}-${v.package}`}
                                        className={`glass-card p-4 border ${sc?.badge === 'badge-critical' ? 'border-red-500/20' : 'border-white/5'}`}
                                    >
                                        <div className="flex items-start justify-between">
                                            <div className="flex items-start gap-3 flex-1">
                                                <Bug size={18} className={`${sc?.text} mt-0.5`} />
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                                                        <span className="text-sm font-bold text-white font-mono">{v.id}</span>
                                                        <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${sc?.badge}`}>{v.severity}</span>
                                                    </div>
                                                    <p className="text-sm text-slate-300 mb-2">{v.description}</p>
                                                    <div className="flex items-center gap-4 text-xs text-slate-400 flex-wrap">
                                                        <span>
                                                            <span className="text-slate-500">Package:</span>{' '}
                                                            <span className="font-mono text-white">{v.package} v{v.version}</span>
                                                        </span>
                                                        <span>
                                                            <span className="text-slate-500">Fixed in:</span>{' '}
                                                            <span className="font-mono text-green-400">v{v.fixed_in}</span>
                                                        </span>
                                                    </div>
                                                    {/* Tips */}
                                                    {tips.length > 0 && (
                                                        <div className="mt-3">
                                                            <button
                                                                type="button"
                                                                onClick={() => toggleTips(v.id)}
                                                                className="flex items-center gap-2 text-xs font-medium text-cyan-400 hover:text-cyan-300"
                                                            >
                                                                <Lightbulb size={14} />
                                                                {tips.length} Tips to fix this
                                                                {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                                            </button>
                                                            {isExpanded && (
                                                                <ul className="mt-2 pl-5 space-y-1.5 text-xs text-slate-300 list-disc">
                                                                    {tips.map((tip, idx) => (
                                                                        <li key={idx}>{tip}</li>
                                                                    ))}
                                                                </ul>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                            <a
                                                href={v.url || `https://nvd.nist.gov/vuln/detail/${v.id}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="p-1.5 rounded-lg hover:bg-white/5 text-slate-400 hover:text-cyan-400 transition-colors shrink-0"
                                            >
                                                <ExternalLink size={14} />
                                            </a>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* SBOM Metadata */}
                    {(metadata?.timestamp || metadata?.component) && (
                        <div className="glass-card p-5">
                            <h3 className="text-sm font-semibold text-slate-300 mb-4">SBOM Metadata</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div className="p-3 rounded-xl bg-dark-800/40 border border-white/5">
                                    <p className="text-xs text-slate-500 mb-1">Timestamp</p>
                                    <p className="text-xs text-slate-300 font-mono">{metadata?.timestamp || '—'}</p>
                                </div>
                                <div className="p-3 rounded-xl bg-dark-800/40 border border-white/5">
                                    <p className="text-xs text-slate-500 mb-1">Component</p>
                                    <p className="text-xs text-slate-300">{metadataComponent?.name || '—'} {metadataComponent?.version ? `(${metadataComponent.version})` : ''}</p>
                                </div>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
