import { useState, useCallback } from 'react';
import { uploadFile } from '../services/api';
import {
    Upload as UploadIcon,
    FileUp,
    CheckCircle2,
    XCircle,
    Loader2,
    FileText,
    AlertTriangle,
    Shield,
} from 'lucide-react';

export default function Upload() {
    const [file, setFile] = useState(null);
    const [dragOver, setDragOver] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleDrop = useCallback((e) => {
        e.preventDefault();
        setDragOver(false);
        const droppedFile = e.dataTransfer.files[0];
        if (droppedFile) {
            setFile(droppedFile);
            setResult(null);
            setError(null);
        }
    }, []);

    const handleFileSelect = (e) => {
        const selectedFile = e.target.files[0];
        if (selectedFile) {
            setFile(selectedFile);
            setResult(null);
            setError(null);
        }
    };

    const handleUpload = async () => {
        if (!file) return;
        setUploading(true);
        setError(null);

        try {
            const { data } = await uploadFile(file);
            setResult(data);
        } catch (err) {
            setError(err.response?.data?.detail || 'Upload failed. Make sure the backend is running.');
        } finally {
            setUploading(false);
        }
    };

    const formatSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    return (
        <div className="max-w-4xl mx-auto space-y-6">
            {/* Header */}
            <div className="text-center mb-8">
                <h1 className="text-2xl font-bold gradient-text mb-2">Upload Network Capture</h1>
                <p className="text-sm text-slate-400">
                    Upload PCAP, PCAPNG, or CSV flow files for ML-powered traffic analysis
                </p>
            </div>

            {/* Drop Zone */}
            <div
                onDrop={handleDrop}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                className={`drop-zone rounded-2xl p-12 text-center cursor-pointer ${dragOver ? 'drag-over' : ''
                    }`}
                onClick={() => document.getElementById('file-input').click()}
            >
                <input
                    id="file-input"
                    type="file"
                    accept=".pcap,.pcapng,.csv"
                    onChange={handleFileSelect}
                    className="hidden"
                />
                <div className="flex flex-col items-center">
                    <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-purple-500/10 border border-cyan-500/20 flex items-center justify-center mb-4">
                        <FileUp size={28} className="text-cyan-400" />
                    </div>
                    <p className="text-base font-semibold text-white mb-1">
                        {dragOver ? 'Drop your file here' : 'Drag & drop your file here'}
                    </p>
                    <p className="text-sm text-slate-400 mb-4">or click to browse</p>
                    <div className="flex gap-2">
                        {['.pcap', '.pcapng', '.csv'].map((ext) => (
                            <span key={ext} className="px-3 py-1 rounded-lg bg-dark-700 text-xs font-mono text-cyan-400 border border-white/5">
                                {ext}
                            </span>
                        ))}
                    </div>
                </div>
            </div>

            {/* Selected File */}
            {file && (
                <div className="glass-card p-4 animate-slide-up">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-xl bg-cyan-500/10">
                                <FileText size={20} className="text-cyan-400" />
                            </div>
                            <div>
                                <p className="text-sm font-medium text-white">{file.name}</p>
                                <p className="text-xs text-slate-400">{formatSize(file.size)}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={() => { setFile(null); setResult(null); setError(null); }}
                                className="text-xs text-slate-400 hover:text-red-400 transition-colors"
                            >
                                Remove
                            </button>
                            <button
                                onClick={handleUpload}
                                disabled={uploading}
                                className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-500 text-white text-sm font-semibold hover:opacity-90 transition-opacity disabled:opacity-50 flex items-center gap-2"
                            >
                                {uploading ? (
                                    <>
                                        <Loader2 size={14} className="animate-spin" />
                                        Processing...
                                    </>
                                ) : (
                                    <>
                                        <UploadIcon size={14} />
                                        Analyze
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Error */}
            {error && (
                <div className="glass-card p-4 border-red-500/20 animate-slide-up">
                    <div className="flex items-center gap-3">
                        <XCircle size={20} className="text-red-400" />
                        <p className="text-sm text-red-300">{error}</p>
                    </div>
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="space-y-4 animate-slide-up">
                    <div className="glass-card p-5 border-green-500/20">
                        <div className="flex items-center gap-3 mb-4">
                            <CheckCircle2 size={20} className="text-green-400" />
                            <h3 className="text-base font-semibold text-white">Analysis Complete</h3>
                        </div>

                        {/* Result KPIs */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
                            <ResultKPI label="Total Flows" value={result.total_flows} icon={FileText} />
                            <ResultKPI label="Anomalies" value={result.anomaly_count} icon={AlertTriangle} />
                            <ResultKPI label="Avg Risk" value={`${Math.round(result.avg_risk_score * 100)}%`} icon={Shield} />
                            <ResultKPI label="File Size" value={formatSize(result.file_size)} icon={FileUp} />
                        </div>

                        {/* Attack Breakdown */}
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Attack Distribution</h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-5">
                            {Object.entries(result.attack_distribution).map(([type, count]) => (
                                <div key={type} className="p-3 rounded-xl bg-dark-800/50 border border-white/5">
                                    <p className="text-xs text-slate-400 mb-1">{type}</p>
                                    <p className="text-lg font-bold text-white">{count}</p>
                                </div>
                            ))}
                        </div>

                        {/* Preview Table */}
                        {result.flows && result.flows.length > 0 && (
                            <>
                                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Sample Flows</h4>
                                <div className="overflow-x-auto">
                                    <table className="w-full data-table">
                                        <thead>
                                            <tr>
                                                <th>Source IP</th>
                                                <th>Dest IP</th>
                                                <th>Protocol</th>
                                                <th>Classification</th>
                                                <th>Risk</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {result.flows.slice(0, 5).map((flow) => (
                                                <tr key={flow.id}>
                                                    <td className="font-mono text-xs">{flow.src_ip}</td>
                                                    <td className="font-mono text-xs">{flow.dst_ip}</td>
                                                    <td>
                                                        <span className="px-2 py-0.5 rounded-md bg-dark-700 text-xs font-mono text-cyan-400">
                                                            {flow.protocol}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span className={`text-xs font-medium ${flow.classification === 'Benign' ? 'text-green-400' : 'text-red-400'}`}>
                                                            {flow.classification}
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
                            </>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

function ResultKPI({ label, value, icon: Icon }) {
    return (
        <div className="p-3 rounded-xl bg-dark-800/50 border border-white/5 text-center">
            <Icon size={16} className="mx-auto text-cyan-400 mb-1" />
            <p className="text-lg font-bold text-white">{value}</p>
            <p className="text-[10px] text-slate-400 uppercase tracking-wider">{label}</p>
        </div>
    );
}
