import { useEffect, useState } from 'react';
import { getOsintFlows } from '../services/api';
import { ShieldCheck, Search, ChevronLeft, ChevronRight } from 'lucide-react';

export default function OSINTValidation() {
    const [flows, setFlows] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [total, setTotal] = useState(0);
    const [monitorView, setMonitorView] = useState(''); // '' = combined, 'passive', 'active'
    const [srcIp, setSrcIp] = useState('');

    const fetchFlows = async () => {
        setLoading(true);
        setError(null);
        try {
            const params = { page, per_page: 20 };
            if (monitorView) params.monitor_type = monitorView;
            if (srcIp.trim()) params.src_ip = srcIp.trim();
            const { data } = await getOsintFlows(params);
            setFlows(data.flows || []);
            setTotal(data.total ?? 0);
            setTotalPages(Math.max(1, data.total_pages ?? 1));
        } catch (e) {
            setError(e.response?.data?.detail || 'Failed to load OSINT-validated flows.');
            setFlows([]);
            setTotal(0);
            setTotalPages(1);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchFlows();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, monitorView]);

    useEffect(() => {
        const t = setTimeout(() => {
            setPage(1);
            fetchFlows();
        }, 350);
        return () => clearTimeout(t);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [srcIp]);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-h1 font-bold text-text-primary flex items-center gap-2">
                        <ShieldCheck size={20} className="text-primary" />
                        OSINT Validation
                    </h1>
                    <p className="text-body text-text-muted mt-1">
                        {total.toLocaleString()} enriched flows
                        {monitorView === 'active' && ' (active monitoring)'}
                        {monitorView === 'passive' && ' (passive / uploads)'}
                        {!monitorView && ' (combined)'}
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <span className="text-small font-medium text-text-muted uppercase tracking-wider">View</span>
                    <div className="flex rounded-xl bg-surface border border-white/10 p-0.5">
                        <button
                            type="button"
                            onClick={() => { setMonitorView(''); setPage(1); }}
                            className={`px-4 py-2 rounded-lg text-body font-medium transition-colors ${!monitorView
                                ? 'bg-primary/15 text-primary border border-primary/30'
                                : 'text-text-muted hover:text-text-primary'}`}
                        >
                            Combined
                        </button>
                        <button
                            type="button"
                            onClick={() => { setMonitorView('active'); setPage(1); }}
                            className={`px-4 py-2 rounded-lg text-body font-medium transition-colors ${monitorView === 'active'
                                ? 'bg-primary/15 text-primary border border-primary/30'
                                : 'text-text-muted hover:text-text-primary'}`}
                        >
                            Active
                        </button>
                        <button
                            type="button"
                            onClick={() => { setMonitorView('passive'); setPage(1); }}
                            className={`px-4 py-2 rounded-lg text-body font-medium transition-colors ${monitorView === 'passive'
                                ? 'bg-primary/15 text-primary border border-primary/30'
                                : 'text-text-muted hover:text-text-primary'}`}
                        >
                            Passive
                        </button>
                    </div>
                </div>
            </div>

            <div className="glass-card p-4 flex items-center gap-3">
                <div className="relative flex-1">
                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                    <input
                        type="text"
                        placeholder="Filter by source IP…"
                        value={srcIp}
                        onChange={(e) => setSrcIp(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 rounded-xl bg-background border border-white/10 text-body text-text-primary placeholder-text-muted focus:outline-none focus:border-primary/50 transition-colors"
                    />
                </div>
                <button
                    type="button"
                    onClick={() => { setSrcIp(''); setPage(1); }}
                    className="px-4 py-2 rounded-[10px] border border-white/10 text-body text-text-muted hover:text-text-primary hover:border-primary/50 transition-colors"
                >
                    Clear
                </button>
            </div>

            {error && (
                <div className="glass-card p-4 border-danger/30 bg-danger/10">
                    <p className="text-body text-red-300">{error}</p>
                </div>
            )}

            <div className="glass-card overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    </div>
                ) : flows.length === 0 ? (
                    <div className="p-10 text-center text-text-muted">
                        No OSINT-enriched flows yet. Generate traffic or upload a file that triggers anomalies with public IPs.
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full data-table">
                            <thead>
                                <tr>
                                    <th>Source</th>
                                    <th>Time</th>
                                    <th>Source IP</th>
                                    <th>Dest IP</th>
                                    <th>OSINT IP</th>
                                    <th>AbuseIPDB</th>
                                    <th>VirusTotal</th>
                                    <th>Final</th>
                                    <th>Verdict</th>
                                    <th>Status</th>
                                    <th>Anomaly</th>
                                    <th>Classification</th>
                                </tr>
                            </thead>
                            <tbody>
                                {flows.map((f) => (
                                    <tr key={f.id}>
                                        <td>
                                            <span className={`px-2 py-0.5 rounded-md text-small font-medium ${(f.monitor_type || 'passive') === 'active' ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-surface text-text-muted border border-white/10'}`}>
                                                {(f.monitor_type || 'passive') === 'active' ? 'Active' : 'Passive'}
                                            </span>
                                        </td>
                                        <td className="text-small text-text-muted whitespace-nowrap">
                                            {f.timestamp ? new Date(f.timestamp).toLocaleString() : '—'}
                                        </td>
                                        <td className="cell-ip">{f.src_ip || '—'}</td>
                                        <td className="cell-ip">{f.dst_ip || '—'}</td>
                                        <td className="cell-ip">{f.osint_ip || '—'}</td>
                                        <td className="text-small font-mono text-text-muted">
                                            {f.abuse_score == null ? '—' : `${Number(f.abuse_score).toFixed(0)}/100`}
                                        </td>
                                        <td className="text-small font-mono text-text-muted">
                                            {f.vt_score == null ? '—' : `${Number(f.vt_score).toFixed(0)}/100`}
                                        </td>
                                        <td className="text-small font-mono text-primary">
                                            {f.final_score == null ? '—' : Number(f.final_score).toFixed(1)}
                                        </td>
                                        <td className="text-small font-semibold text-text-primary">
                                            {f.final_verdict || '—'}
                                        </td>
                                        <td className="text-small text-text-muted">
                                            {f.osint_error ? String(f.osint_error) : ((f.abuse_ok || f.vt_ok) ? 'OK' : '—')}
                                        </td>
                                        <td className="text-small font-mono text-danger">
                                            {(Number(f.anomaly_score) || 0).toFixed(2)}
                                        </td>
                                        <td className="text-small font-semibold text-text-primary">
                                            {f.classification || '—'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {flows.length > 0 && (
                    <div className="flex items-center justify-between px-6 py-3 border-t border-white/10">
                        <p className="text-small text-text-muted">
                            Page {page} / {totalPages}
                        </p>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setPage(Math.max(1, page - 1))}
                                disabled={page === 1}
                                className="p-2 rounded-[10px] border border-white/10 text-text-muted hover:text-text-primary hover:border-primary/50 disabled:opacity-30 transition-colors"
                            >
                                <ChevronLeft size={14} />
                            </button>
                            <button
                                onClick={() => setPage(Math.min(totalPages, page + 1))}
                                disabled={page === totalPages}
                                className="p-2 rounded-[10px] border border-white/10 text-text-muted hover:text-text-primary hover:border-primary/50 disabled:opacity-30 transition-colors"
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

