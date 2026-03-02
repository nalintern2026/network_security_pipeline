import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getHistory } from '../services/api';
import {
    History as HistoryIcon,
    FileText,
    ChevronRight,
    AlertTriangle,
    Loader2,
    Clock,
    HardDrive,
} from 'lucide-react';

export default function History() {
    const [analyses, setAnalyses] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        loadHistory();
    }, []);

    const loadHistory = async () => {
        setLoading(true);
        setError(null);
        try {
            const { data } = await getHistory();
            setAnalyses(data.analyses || []);
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load history.');
        } finally {
            setLoading(false);
        }
    };

    const formatSize = (bytes) => {
        if (bytes == null || bytes === undefined) return '—';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const formatDate = (iso) => {
        if (!iso) return '—';
        try {
            const d = new Date(iso);
            return d.toLocaleString();
        } catch {
            return iso;
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[300px]">
                <Loader2 size={32} className="animate-spin text-cyan-400" />
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto space-y-6">
            <div className="text-center mb-8">
                <h1 className="text-2xl font-bold gradient-text mb-2">Analysis History</h1>
                <p className="text-sm text-slate-400">
                    View past analyses. Click any report to open full details in a new page.
                </p>
            </div>

            {error && (
                <div className="glass-card p-4 border-red-500/20">
                    <div className="flex items-center gap-3">
                        <AlertTriangle size={20} className="text-red-400" />
                        <p className="text-sm text-red-300">{error}</p>
                    </div>
                </div>
            )}

            {analyses.length === 0 && !loading && (
                <div className="glass-card p-12 text-center">
                    <HistoryIcon size={48} className="mx-auto text-slate-500 mb-4" />
                    <p className="text-slate-400">No analysis history yet.</p>
                    <p className="text-sm text-slate-500 mt-2">Upload and analyze files on the Upload page to see them here.</p>
                </div>
            )}

            <div className="space-y-3">
                {analyses.map((a) => (
                    <button
                        key={a.analysis_id}
                        type="button"
                        onClick={() => navigate(`/history/${a.analysis_id}`)}
                        className="w-full glass-card p-4 flex items-center justify-between gap-4 text-left hover:bg-white/5 hover:border-cyan-400/30 transition-all group"
                    >
                        <div className="flex items-center gap-4 min-w-0 flex-1">
                            <div className="p-2 rounded-xl bg-cyan-500/10 flex-shrink-0">
                                <FileText size={20} className="text-cyan-400" />
                            </div>
                            <div className="min-w-0 flex-1">
                                <p className="text-sm font-medium text-white truncate group-hover:text-cyan-300">{a.filename || 'Unknown'}</p>
                                <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1.5 text-xs text-slate-400">
                                    <span className="flex items-center gap-1">
                                        <Clock size={12} />
                                        {formatDate(a.uploaded_at)}
                                    </span>
                                    <span className="flex items-center gap-1">
                                        <HardDrive size={12} />
                                        {formatSize(a.file_size)}
                                    </span>
                                    <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300">
                                        {a.monitor_type || 'Static Monitoring'}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-4 flex-shrink-0">
                            <div className="text-right">
                                <p className="text-[10px] text-slate-500 uppercase">Flows</p>
                                <p className="text-sm font-semibold text-white">{a.total_flows ?? 0}</p>
                            </div>
                            <div className="text-right">
                                <p className="text-[10px] text-slate-500 uppercase">Anomalies</p>
                                <p className="text-sm font-semibold text-amber-400">{a.anomaly_count ?? 0}</p>
                            </div>
                            <div className="text-right">
                                <p className="text-[10px] text-slate-500 uppercase">Avg Risk</p>
                                <p className="text-sm font-semibold text-white">{Math.round((a.avg_risk_score ?? 0) * 100)}%</p>
                            </div>
                            <ChevronRight size={20} className="text-slate-400 group-hover:text-cyan-400" />
                        </div>
                    </button>
                ))}
            </div>
        </div>
    );
}
