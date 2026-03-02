import { useState, useEffect } from 'react';
import {
    startRealtimeMonitor,
    stopRealtimeMonitor,
    getRealtimeStatus,
    getRealtimeInterfaces,
} from '../services/api';
import {
    Radio,
    Play,
    Square,
    Loader2,
    AlertTriangle,
    CheckCircle2,
    Wifi,
    Activity,
} from 'lucide-react';

export default function ActiveMonitoring() {
    const [status, setStatus] = useState(null);
    const [interfaces, setInterfaces] = useState([]);
    const [selectedInterface, setSelectedInterface] = useState('');
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(false);
    const [error, setError] = useState(null);
    const [lastUpdated, setLastUpdated] = useState(null);

    const fetchStatus = async () => {
        try {
            const { data } = await getRealtimeStatus();
            setStatus(data);
            setLastUpdated(new Date().toLocaleTimeString());
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to fetch status');
        }
    };

    const fetchInterfaces = async () => {
        try {
            const { data } = await getRealtimeInterfaces();
            setInterfaces(data.interfaces || []);
            if (!selectedInterface && data.interfaces?.length) {
                setSelectedInterface(data.interfaces[0] || '');
            }
        } catch (err) {
            setInterfaces(['lo', 'eth0', 'enp0s3']);
        }
    };

    useEffect(() => {
        const load = async () => {
            setLoading(true);
            setError(null);
            await Promise.all([fetchStatus(), fetchInterfaces()]);
            setLoading(false);
        };
        load();
    }, []);

    // Refresh every 2s when capturing (live updates), 5s when stopped
    useEffect(() => {
        const intervalMs = status?.running ? 2000 : 5000;
        const interval = setInterval(fetchStatus, intervalMs);
        return () => clearInterval(interval);
    }, [status?.running]);

    const handleStart = async () => {
        setActionLoading(true);
        setError(null);
        try {
            const { data } = await startRealtimeMonitor(selectedInterface);
            if (data.status === 'error') {
                setError(data.message || 'Failed to start');
            } else {
                await fetchStatus();
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to start monitoring');
        } finally {
            setActionLoading(false);
        }
    };

    const handleStop = async () => {
        setActionLoading(true);
        setError(null);
        try {
            await stopRealtimeMonitor();
            await fetchStatus();
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to stop monitoring');
        } finally {
            setActionLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <Loader2 size={32} className="animate-spin text-cyan-400" />
            </div>
        );
    }

    return (
        <div className="max-w-2xl mx-auto space-y-6">
            <div className="text-center mb-8">
                <h1 className="text-2xl font-bold gradient-text mb-2">Active Monitoring</h1>
                <p className="text-sm text-slate-400">
                    Live packet capture and flow analysis. Run backend with <code className="px-1.5 py-0.5 rounded bg-dark-700 text-cyan-400">sudo</code> for packet sniffing.
                </p>
            </div>

            {error && (
                <div className="glass-card p-4 border-amber-500/20 flex items-center gap-3">
                    <AlertTriangle size={20} className="text-amber-400 shrink-0" />
                    <p className="text-sm text-amber-200">{error}</p>
                </div>
            )}

            <div className="glass-card p-6 border border-cyan-500/20">
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-3 rounded-xl bg-cyan-500/10">
                        <Radio size={24} className="text-cyan-400" />
                    </div>
                    <div>
                        <h3 className="text-lg font-semibold text-white">Monitor Control</h3>
                        <p className="text-xs text-slate-400">Start or stop live packet capture</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <div>
                        <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
                            Network Interface
                        </label>
                        <select
                            value={selectedInterface}
                            onChange={(e) => setSelectedInterface(e.target.value)}
                            disabled={status?.running}
                            className="w-full px-4 py-3 rounded-xl bg-dark-800 border border-white/5 text-white focus:outline-none focus:border-cyan-500/30 disabled:opacity-60"
                        >
                            <option value="">Default (lo – captures local API traffic)</option>
                            {interfaces.map((iface) => (
                                <option key={iface} value={iface}>
                                    {iface === 'lo' ? `${iface} (loopback, try first)` : iface}
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="flex gap-3">
                        <button
                            onClick={handleStart}
                            disabled={status?.running || actionLoading}
                            className="flex-1 px-4 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-500 text-white font-semibold hover:opacity-90 disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                            {actionLoading ? (
                                <Loader2 size={18} className="animate-spin" />
                            ) : (
                                <Play size={18} />
                            )}
                            Start
                        </button>
                        <button
                            onClick={handleStop}
                            disabled={!status?.running || actionLoading}
                            className="flex-1 px-4 py-3 rounded-xl border border-red-500/40 text-red-400 font-semibold hover:bg-red-500/10 disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                            <Square size={18} />
                            Stop
                        </button>
                    </div>
                </div>
            </div>

            <div className="glass-card p-6">
                <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                    <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                        <Activity size={16} className="text-cyan-400" />
                        Status
                    </h3>
                    <span className="text-xs text-slate-500">
                        {status?.running ? (
                            <>
                                <span className="text-cyan-400 font-medium">Live • </span>
                                updates every 2s • Last: {lastUpdated || '—'}
                            </>
                        ) : (
                            <>Last updated: {lastUpdated || '—'}</>
                        )}
                    </span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 rounded-xl bg-dark-800/50 border border-white/5">
                        <p className="text-xs text-slate-500 mb-1">State</p>
                        <p className={`text-lg font-bold ${status?.running ? 'text-green-400' : 'text-slate-400'}`}>
                            {status?.running ? (
                                <span className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                                    Running
                                </span>
                            ) : (
                                'Stopped'
                            )}
                        </p>
                    </div>
                    <div className="p-4 rounded-xl bg-dark-800/50 border border-white/5">
                        <p className="text-xs text-slate-500 mb-1">Interface</p>
                        <p className="text-sm font-mono text-white">{status?.interface || '—'}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-dark-800/50 border border-white/5">
                        <p className="text-xs text-slate-500 mb-1">Capture Windows</p>
                        <p className="text-lg font-bold text-cyan-400">{status?.capture_count ?? 0}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-dark-800/50 border border-white/5">
                        <p className="text-xs text-slate-500 mb-1">Last Batch Flows</p>
                        <p className="text-lg font-bold text-cyan-400">{status?.last_flow_count ?? 0}</p>
                    </div>
                    {status?.flow_counts && (
                        <div className="p-4 rounded-xl bg-dark-800/50 border border-white/5 col-span-2">
                            <p className="text-xs text-slate-500 mb-1">Total in DB (active / passive)</p>
                            <p className="text-sm font-mono text-white">
                                active: {status.flow_counts.active ?? 0} | passive: {status.flow_counts.passive ?? 0}
                            </p>
                            {(status.flow_counts.active ?? 0) === 0 && status?.running && !status?.capture_error && (
                                <p className="text-xs text-amber-400 mt-1">Capturing on loopback. Use the app (refresh Dashboard) to generate traffic.</p>
                            )}
                        </div>
                    )}
                    {status?.capture_error && (
                        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 col-span-2">
                            <p className="text-xs text-red-400 font-medium mb-1">Capture error</p>
                            <p className="text-sm text-red-300 font-mono break-all">{status.capture_error}</p>
                            <p className="text-xs text-amber-400 mt-2">Run backend with sudo: <code className="px-1 rounded bg-dark-700">cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000</code></p>
                        </div>
                    )}
                </div>
                {!status?.running && (
                    <p className="text-amber-400/90 text-sm mt-4 flex items-center gap-2">
                        <Play size={16} />
                        Click <strong>Start</strong> above to begin live capture. Backend must run with sudo.
                    </p>
                )}
            </div>

            <div className="glass-card p-6 border border-cyan-500/10">
                <div className="flex items-start gap-3">
                    <AlertTriangle size={20} className="text-cyan-400 shrink-0 mt-0.5" />
                    <div className="text-sm text-slate-300 space-y-2">
                        <p>
                            <strong>Note:</strong> Active monitoring captures packets from the selected interface.
                            Flows are classified and inserted into the database with <code className="px-1 rounded bg-dark-700">monitor_type=active</code>.
                        </p>
                        <p>
                            The Dashboard shows aggregated data from both passive uploads and active monitoring.
                            Refresh the Dashboard to see live updates.
                        </p>
                        <p className="text-slate-500 text-xs">
                            <strong>Must run backend with sudo</strong> for live capture: <code className="px-1 rounded bg-dark-700">cd nal/backend && sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000</code>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
