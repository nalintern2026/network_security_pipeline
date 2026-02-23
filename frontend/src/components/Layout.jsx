import { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Upload,
    Network,
    AlertTriangle,
    BarChart3,
    Shield,
    Menu,
    X,
    Activity,
    Wifi,
} from 'lucide-react';
import { checkHealth } from '../services/api';

const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/upload', label: 'Upload', icon: Upload },
    { path: '/traffic', label: 'Traffic Analysis', icon: Network },
    { path: '/anomalies', label: 'Anomalies', icon: AlertTriangle },
    { path: '/models', label: 'Model Performance', icon: BarChart3 },
    { path: '/security', label: 'SBOM Security', icon: Shield },
];

export default function Layout({ children }) {
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const [apiStatus, setApiStatus] = useState('checking');
    const location = useLocation();
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
    let apiHost = 'localhost:8000';
    try {
        apiHost = new URL(apiUrl).origin;
    } catch {
        apiHost = apiUrl;
    }

    const checkApi = async () => {
        try {
            await checkHealth();
            setApiStatus('connected');
        } catch {
            setApiStatus('disconnected');
        }
    };

    useEffect(() => {
        checkApi();
        const interval = setInterval(checkApi, 30000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="flex h-screen bg-dark-900 bg-grid">
            {/* Sidebar */}
            <aside
                className={`${sidebarOpen ? 'w-64' : 'w-20'
                    } fixed h-full z-30 transition-all duration-300 ease-in-out`}
                style={{
                    background: 'linear-gradient(180deg, rgba(15,22,41,0.97) 0%, rgba(10,14,26,0.99) 100%)',
                    borderRight: '1px solid rgba(0, 212, 255, 0.08)',
                }}
            >
                {/* Logo */}
                <div className="flex items-center justify-between h-16 px-4 border-b border-white/5">
                    <div className="flex items-center gap-3">
                        <div className="relative">
                            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 to-purple-500 flex items-center justify-center">
                                <Wifi size={18} className="text-white" />
                            </div>
                            <div className="absolute -top-0.5 -right-0.5 w-3 h-3 rounded-full bg-green-400 border-2 border-dark-900 animate-pulse" />
                        </div>
                        {sidebarOpen && (
                            <div className="animate-fade-in">
                                <h1 className="text-sm font-bold gradient-text leading-tight">NetGuard</h1>
                                <p className="text-[10px] text-slate-500 font-medium">Security Intelligence</p>
                            </div>
                        )}
                    </div>
                    <button
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                        className="p-1.5 rounded-lg hover:bg-white/5 text-slate-400 hover:text-white transition-colors"
                    >
                        {sidebarOpen ? <X size={16} /> : <Menu size={16} />}
                    </button>
                </div>

                {/* Nav Links */}
                <nav className="mt-4 px-3 space-y-1">
                    {navItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = location.pathname === item.path;
                        return (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 group ${isActive
                                        ? 'bg-gradient-to-r from-cyan-500/10 to-purple-500/10 text-cyan-400 border border-cyan-500/20'
                                        : 'text-slate-400 hover:text-white hover:bg-white/5'
                                    }`}
                            >
                                <Icon
                                    size={18}
                                    className={`flex-shrink-0 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'
                                        }`}
                                />
                                {sidebarOpen && <span>{item.label}</span>}
                            </NavLink>
                        );
                    })}
                </nav>

                {/* Status indicator */}
                <div className="absolute bottom-4 left-3 right-3">
                    <div className={`glass-card p-3 ${sidebarOpen ? '' : 'flex justify-center'}`}>
                        <div className="flex items-center gap-2">
                            <div className="relative">
                                <div
                                    className={`w-2.5 h-2.5 rounded-full ${apiStatus === 'connected'
                                            ? 'bg-green-400'
                                            : apiStatus === 'disconnected'
                                                ? 'bg-red-400'
                                                : 'bg-yellow-400 animate-pulse'
                                        }`}
                                />
                                {apiStatus === 'connected' && (
                                    <div className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-green-400 animate-ping-slow" />
                                )}
                            </div>
                            {sidebarOpen && (
                                <div className="animate-fade-in flex flex-col gap-0.5">
                                    <p className="text-xs font-medium text-slate-300">
                                        {apiStatus === 'connected' ? 'API Connected' : apiStatus === 'disconnected' ? 'API Offline' : 'Checking...'}
                                    </p>
                                    <p className="text-[10px] text-slate-500">
                                        {apiStatus === 'disconnected' ? (
                                            <button type="button" onClick={checkApi} className="text-cyan-400 hover:underline">Retry</button>
                                        ) : (
                                            apiHost
                                        )}
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className={`flex-1 ${sidebarOpen ? 'ml-64' : 'ml-20'} transition-all duration-300 overflow-y-auto`}>
                {/* Top Bar */}
                <header className="sticky top-0 z-20 h-14 flex items-center justify-between px-6"
                    style={{
                        background: 'rgba(10, 14, 26, 0.8)',
                        backdropFilter: 'blur(12px)',
                        borderBottom: '1px solid rgba(255,255,255,0.04)',
                    }}
                >
                    <div className="flex items-center gap-3">
                        <Activity size={16} className="text-cyan-400" />
                        <h2 className="text-sm font-semibold text-slate-200">
                            {navItems.find(n => n.path === location.pathname)?.label || 'Dashboard'}
                        </h2>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                            <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                            Live Monitoring
                        </div>
                    </div>
                </header>

                {apiStatus === 'disconnected' && (
                    <div className="mx-6 mt-4 rounded-xl border border-amber-500/25 bg-amber-500/10 px-4 py-3 flex items-center justify-between gap-3">
                        <p className="text-xs text-amber-200">
                            Backend is offline. UI is still available; live data updates will resume when API is back.
                        </p>
                        <button
                            type="button"
                            onClick={checkApi}
                            className="px-3 py-1.5 rounded-lg text-xs font-medium border border-cyan-500/35 text-cyan-300 hover:bg-cyan-500/15 transition-colors"
                        >
                            Retry Connection
                        </button>
                    </div>
                )}

                {/* Page Content */}
                <div className="p-6 animate-fade-in">
                    {children}
                </div>
            </main>
        </div>
    );
}
