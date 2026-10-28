import { useCallback, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  Gauge,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  TrendingUp,
  Upload,
  X,
} from 'lucide-react'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000',
  timeout: 15000,
})

type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

interface AlertRecord {
  alert_id: string
  timestamp: string
  severity: Severity
  category: string
  source_ip: string
  destination_ip: string
  risk_score: number
  confidence: number
  confidence_type?: string
  prediction: 'benign' | 'malicious'
  reasons: string[]
  rule_indicators?: { rule_id: string; reason: string; weight: number }[]
  metadata?: Record<string, unknown>
  created_at?: string
}

interface DashboardSummary {
  total_records: number
  total_threats: number
  high_and_critical: number
  benign_count: number
  suspicious_count: number
  severity_counts: Record<string, number>
  alert_trends: { label: string; threats: number; benign: number }[]
  database_mode: string
  demo_mode: boolean
}

interface ModelMetrics {
  evaluation_type: string
  dataset_type: string
  dataset_rows?: number
  best_model: string
  training_timestamp?: string
  notes: string
  results: Record<string, {
    precision: number
    recall: number
    f1_score: number
    roc_auc: number | null
    confusion_matrix: number[][]
    n_samples: number
  }>
}

interface DetectionSettings {
  alert_threshold: number
  risk_threshold: number
  portscan_threshold: number
  dos_threshold: number
  anomaly_threshold: number
}

const severityColors: Record<string, string> = {
  LOW: '#4ade80',
  MEDIUM: '#fbbf24',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
}

const initialRecord = {
  src_ip: '10.0.0.15',
  dst_ip: '192.168.10.20',
  protocol: 'TCP',
  src_port: 49152,
  dst_port: 22,
  duration: 3.2,
  bytes_sent: 12500,
  bytes_received: 6340,
  packet_count: 210,
  failed_login_count: 6,
  login_attempts: 9,
  connection_state: 'SYN_SCAN',
  traffic_volume: 420,
  anomaly_score: 0.81,
  is_simulated: true,
}

const defaultSettings: DetectionSettings = {
  alert_threshold: 0.5,
  risk_threshold: 65,
  portscan_threshold: 0.6,
  dos_threshold: 0.7,
  anomaly_threshold: 0.58,
}

function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (detail && typeof detail === 'object') return JSON.stringify(detail)
    return error.message || 'The backend could not be reached.'
  }
  return error instanceof Error ? error.message : 'An unexpected error occurred.'
}

function App() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [alertTotal, setAlertTotal] = useState(0)
  const [events, setEvents] = useState<{ event_type: string; timestamp: string; payload?: AlertRecord }[]>([])
  const [modelStatus, setModelStatus] = useState<{ status: string; feature_schema: string[]; evaluation_type?: string } | null>(null)
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null)
  const [settings, setSettings] = useState<DetectionSettings>(defaultSettings)
  const [settingsSaved, setSettingsSaved] = useState(false)
  const [record, setRecord] = useState(initialRecord)
  const [analysisResult, setAnalysisResult] = useState<Record<string, unknown> | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null)
  const [alertPage, setAlertPage] = useState(1)
  const [alertFilter, setAlertFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [datasetFile, setDatasetFile] = useState<File | null>(null)
  const [datasetBusy, setDatasetBusy] = useState(false)
  const [datasetValidation, setDatasetValidation] = useState<Record<string, unknown> | null>(null)
  const [datasetResult, setDatasetResult] = useState<Record<string, unknown> | null>(null)
  const [datasetError, setDatasetError] = useState('')

  const loadDashboard = useCallback(async () => {
    setRefreshing(true)
    try {
      const [dashboard, model, alertResponse, eventResponse, metricResponse, settingsResponse] = await Promise.all([
        api.get<DashboardSummary>('/api/dashboard/summary'),
        api.get('/api/models/status'),
        api.get('/api/alerts', {
          params: {
            page: alertPage,
            page_size: 5,
            severity: alertFilter !== 'all' ? alertFilter : undefined,
            category: categoryFilter || undefined,
            search: search.trim() || undefined,
          },
        }),
        api.get('/api/events', { params: { limit: 8 } }),
        api.get<ModelMetrics>('/api/models/metrics'),
        api.get('/api/settings'),
      ])
      setSummary(dashboard.data)
      setModelStatus(model.data)
      setAlerts(alertResponse.data.items ?? [])
      setAlertTotal(alertResponse.data.total ?? 0)
      setEvents(eventResponse.data.items ?? [])
      setMetrics(metricResponse.data)
      setSettings({ ...defaultSettings, ...settingsResponse.data.settings })
      setError('')
    } catch (loadError) {
      setError(errorMessage(loadError))
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [alertFilter, alertPage, categoryFilter, search])

  useEffect(() => {
    const timer = window.setTimeout(() => void loadDashboard(), 250)
    return () => window.clearTimeout(timer)
  }, [loadDashboard])

  const pieData = useMemo(() => [
    { name: 'Benign', value: summary?.benign_count ?? 0 },
    { name: 'Suspicious', value: summary?.suspicious_count ?? 0 },
  ], [summary])

  const pageCount = Math.ceil(alertTotal / 5)
  const summaryCards = [
    { label: 'Analyzed records', value: summary?.total_records ?? 0, icon: <Activity className="h-5 w-5" /> },
    { label: 'Detected threats', value: summary?.total_threats ?? 0, icon: <ShieldAlert className="h-5 w-5" /> },
    { label: 'High / Critical', value: summary?.high_and_critical ?? 0, icon: <AlertTriangle className="h-5 w-5" /> },
    { label: 'Model status', value: modelStatus?.status ?? 'unknown', icon: <Gauge className="h-5 w-5" /> },
  ]

  const handleRecordChange = (field: string, value: string | number | boolean) => {
    setRecord((current) => ({ ...current, [field]: value }))
  }

  const handleAnalyze = async () => {
    setLoading(true)
    try {
      const { data } = await api.post('/api/analyze/record', record)
      setAnalysisResult(data)
      await loadDashboard()
    } catch (analysisError) {
      setAnalysisResult({ error: errorMessage(analysisError) })
    } finally {
      setLoading(false)
    }
  }

  const handleDatasetValidate = async () => {
    if (!datasetFile) return
    setDatasetBusy(true)
    setDatasetError('')
    setDatasetResult(null)
    setDatasetValidation(null)
    try {
      const form = new FormData()
      form.append('file', datasetFile)
      const { data } = await api.post('/api/datasets/validate', form)
      setDatasetValidation(data)
    } catch (validationError) {
      setDatasetError(errorMessage(validationError))
    } finally {
      setDatasetBusy(false)
    }
  }

  const handleDatasetAnalyze = async () => {
    if (!datasetFile) return
    setDatasetBusy(true)
    setDatasetError('')
    setDatasetResult(null)
    try {
      const form = new FormData()
      form.append('file', datasetFile)
      const { data } = await api.post('/api/datasets/analyze', form)
      setDatasetResult(data)
      await loadDashboard()
    } catch (analysisError) {
      setDatasetError(errorMessage(analysisError))
    } finally {
      setDatasetBusy(false)
    }
  }

  const downloadDatasetReport = () => {
    if (!datasetResult) return
    const blob = new Blob([JSON.stringify(datasetResult, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'threatlens-analysis-report.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  const saveSettings = async () => {
    setSettingsSaved(false)
    try {
      const { data } = await api.put('/api/settings', settings)
      setSettings(data.settings)
      setSettingsSaved(true)
      setError('')
    } catch (settingsError) {
      setError(errorMessage(settingsError))
    }
  }

  const onDatasetFileChanged = (file: File | null) => {
    setDatasetFile(file)
    setDatasetValidation(null)
    setDatasetResult(null)
    setDatasetError('')
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <header className="mb-6 flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-panel md:flex-row md:items-center md:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-3 text-sm uppercase tracking-[0.2em] text-cyan-300">
              <Shield className="h-4 w-4" /> ThreatLens AI
            </div>
            <h1 className="text-2xl font-semibold text-white">Cybersecurity Threat Intelligence</h1>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
            <span className="inline-flex items-center gap-2 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-amber-200">
              {summary?.demo_mode ? 'Demo mode enabled' : 'Configured mode'}
            </span>
            <Database className="h-4 w-4 text-cyan-300" />
            <span>{summary?.database_mode ?? 'Checking persistence...'}</span>
            <button
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 hover:bg-slate-800 disabled:opacity-50"
              onClick={() => void loadDashboard()}
              disabled={refreshing}
              aria-label="Refresh dashboard"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        </header>

        {error && (
          <div role="alert" className="mb-6 flex flex-col gap-3 rounded-xl border border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200 sm:flex-row sm:items-center sm:justify-between">
            <span>Backend unavailable or request failed: {error}</span>
            <button className="rounded-lg border border-red-400/40 px-3 py-1.5 hover:bg-red-900/50" onClick={() => void loadDashboard()}>
              Retry
            </button>
          </div>
        )}

        {loading && !summary && (
          <div role="status" className="mb-6 rounded-xl border border-slate-800 bg-slate-900 p-4 text-slate-300">
            Connecting to the ThreatLens API...
          </div>
        )}

        <section className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {summaryCards.map((card) => (
            <div key={card.label} className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
              <div className="mb-4 flex items-center justify-between text-sm text-slate-300">
                <span>{card.label}</span>
                <span className="rounded-lg bg-slate-800 p-2 text-cyan-300">{card.icon}</span>
              </div>
              <div className="text-3xl font-semibold text-white">{String(card.value)}</div>
            </div>
          ))}
        </section>

        <section className="mb-6 grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Threat trend</h2>
              <TrendingUp className="h-5 w-5 text-cyan-300" />
            </div>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={summary?.alert_trends ?? []}>
                  <defs>
                    <linearGradient id="threatFill" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                  <XAxis dataKey="label" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" allowDecimals={false} />
                  <Tooltip />
                  <Area type="monotone" dataKey="threats" stroke="#38bdf8" fill="url(#threatFill)" />
                  <Area type="monotone" dataKey="benign" stroke="#4ade80" fillOpacity={0} />
                </AreaChart>
              </ResponsiveContainer>
              {!summary?.alert_trends.length && <p className="mt-2 text-center text-sm text-slate-500">Analyze traffic to populate this chart.</p>}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-4 text-lg font-semibold text-white">Traffic classification mix</h2>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} label>
                    {pieData.map((entry, index) => <Cell key={entry.name} fill={index === 0 ? '#22c55e' : '#f87171'} />)}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
              {!summary?.total_records && <p className="mt-2 text-center text-sm text-slate-500">No analyzed records yet.</p>}
            </div>
          </div>
        </section>

        <section className="mb-6 grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-4 text-lg font-semibold text-white">Severity distribution</h2>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={Object.entries(summary?.severity_counts ?? {}).map(([name, count]) => ({ name, count }))}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                  <XAxis dataKey="name" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="count">
                    {Object.keys(summary?.severity_counts ?? {}).map((key) => <Cell key={key} fill={severityColors[key] ?? '#60a5fa'} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <div className="mb-4 flex flex-col gap-3">
              <h2 className="text-lg font-semibold text-white">Threat intelligence</h2>
              <div className="grid gap-2 sm:grid-cols-[1fr_150px_190px]">
                <label className="relative">
                  <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                  <input
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-sm text-slate-100"
                    placeholder="Search IP, category, alert ID"
                    value={search}
                    onChange={(event) => { setSearch(event.target.value); setAlertPage(1) }}
                  />
                </label>
                <select className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-sm text-slate-200" value={alertFilter} onChange={(event) => { setAlertFilter(event.target.value); setAlertPage(1) }}>
                  <option value="all">All severities</option>
                  {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as Severity[]).map((value) => <option key={value}>{value}</option>)}
                </select>
                <select className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-sm text-slate-200" value={categoryFilter} onChange={(event) => { setCategoryFilter(event.target.value); setAlertPage(1) }}>
                  <option value="">All categories</option>
                  <option value="brute_force_like_activity">Brute-force-like</option>
                  <option value="port_scan_like_activity">Scan-like</option>
                  <option value="denial_of_service_like_traffic">High-volume / DoS-like</option>
                  <option value="suspicious_network_activity">Suspicious activity</option>
                  <option value="benign">Benign</option>
                </select>
              </div>
            </div>
            <div className="space-y-3">
              {alerts.length === 0 ? (
                <div className="rounded-xl border border-dashed border-slate-700 p-4 text-slate-400">
                  {summary?.total_records ? 'No alerts match these filters.' : 'No analyzed traffic yet. Use the record or CSV analyzer below.'}
                </div>
              ) : alerts.map((alert) => (
                <button key={alert.alert_id} onClick={() => setSelectedAlert(alert)} className="block w-full rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-left hover:border-slate-600">
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <span className="text-sm font-medium text-white">{alert.category.replaceAll('_', ' ')}</span>
                    <span className="rounded-full border px-2 py-0.5 text-xs font-medium" style={{ borderColor: severityColors[alert.severity], color: severityColors[alert.severity] }}>{alert.severity}</span>
                  </div>
                  <div className="text-xs text-slate-400">{alert.source_ip} → {alert.destination_ip}</div>
                  <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
                    <span>Risk {alert.risk_score} · {alert.prediction}</span>
                    <span>Confidence {Number(alert.confidence).toFixed(3)}</span>
                  </div>
                </button>
              ))}
            </div>
            <div className="mt-4 flex items-center justify-between text-sm text-slate-300">
              <button className="rounded-lg border border-slate-700 px-3 py-1.5 hover:bg-slate-800 disabled:opacity-40" onClick={() => setAlertPage((page) => Math.max(1, page - 1))} disabled={alertPage <= 1}>Previous</button>
              <span>{alertTotal} alerts · Page {alertTotal ? alertPage : 0} of {pageCount}</span>
              <button className="rounded-lg border border-slate-700 px-3 py-1.5 hover:bg-slate-800 disabled:opacity-40" onClick={() => setAlertPage((page) => page + 1)} disabled={!pageCount || alertPage >= pageCount}>Next</button>
            </div>
          </div>
        </section>

        <section className="mb-6 grid gap-6 xl:grid-cols-2">
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-4 text-lg font-semibold text-white">Analyze traffic record</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(record).map(([key, value]) => {
                if (key === 'is_simulated') {
                  return (
                    <label key={key} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 p-2 text-sm text-slate-300">
                      Synthetic demo input
                      <input type="checkbox" checked={Boolean(value)} onChange={(event) => handleRecordChange(key, event.target.checked)} />
                    </label>
                  )
                }
                if (key === 'protocol' || key === 'connection_state') {
                  const options = key === 'protocol'
                    ? ['TCP', 'UDP']
                    : ['ESTABLISHED', 'SYN_SCAN', 'SYN_SENT', 'TIME_WAIT', 'FIN_WAIT', 'REJECTED']
                  return (
                    <label key={key} className="text-sm text-slate-300">
                      <span className="mb-1 block capitalize">{key.replaceAll('_', ' ')}</span>
                      <select className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100" value={String(value)} onChange={(event) => handleRecordChange(key, event.target.value)}>
                        {options.map((option) => <option key={option}>{option}</option>)}
                      </select>
                    </label>
                  )
                }
                return (
                  <label key={key} className="text-sm text-slate-300">
                    <span className="mb-1 block capitalize">{key.replaceAll('_', ' ')}</span>
                    <input
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100"
                      type={typeof value === 'string' ? 'text' : 'number'}
                      min={typeof value === 'number' && key !== 'anomaly_score' ? 0 : undefined}
                      max={key === 'anomaly_score' ? 1 : undefined}
                      step={key === 'anomaly_score' ? 0.01 : 'any'}
                      value={String(value)}
                      onChange={(event) => handleRecordChange(key, typeof value === 'number' ? Number(event.target.value) : event.target.value)}
                    />
                  </label>
                )
              })}
            </div>
            <button className="mt-4 w-full rounded-xl bg-cyan-500 px-4 py-2 font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-50" onClick={() => void handleAnalyze()} disabled={loading}>
              {loading ? 'Analyzing...' : 'Analyze record'}
            </button>
            {analysisResult && (
              <div className="mt-4 rounded-xl border border-slate-700 bg-slate-950/70 p-3 text-sm text-slate-200">
                {'error' in analysisResult ? <p role="alert" className="text-red-400">{String(analysisResult.error)}</p> : (
                  <>
                    <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 font-medium text-white">
                      <span>Prediction: {String(analysisResult.prediction)}</span>
                      <span>Risk: {String(analysisResult.risk_score)} / 100</span>
                      <span>Severity: {String(analysisResult.severity)}</span>
                    </div>
                    <div className="text-xs text-slate-400">Model confidence: {Number(analysisResult.confidence).toFixed(3)} (uncalibrated)</div>
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-slate-300">
                      {(analysisResult.reasons as string[]).map((reason) => <li key={reason}>{reason}</li>)}
                    </ul>
                  </>
                )}
              </div>
            )}
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <div className="mb-4 flex items-center gap-2">
              <Upload className="h-5 w-5 text-cyan-300" />
              <h2 className="text-lg font-semibold text-white">CSV dataset analysis</h2>
            </div>
            <p className="mb-3 text-sm text-slate-400">CSV must contain the supported traffic schema. Uploads are processed in memory and not retained as files.</p>
            <input
              className="block w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-slate-100"
              type="file"
              accept=".csv,text/csv"
              onChange={(event) => onDatasetFileChanged(event.target.files?.[0] ?? null)}
            />
            <div className="mt-3 flex flex-wrap gap-2">
              <button className="rounded-lg border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800 disabled:opacity-40" disabled={!datasetFile || datasetBusy} onClick={() => void handleDatasetValidate()}>
                Validate CSV
              </button>
              <button className="rounded-lg bg-cyan-500 px-3 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-40" disabled={!datasetFile || datasetBusy || datasetValidation?.valid !== true} onClick={() => void handleDatasetAnalyze()}>
                {datasetBusy ? 'Processing...' : 'Run analysis'}
              </button>
              {datasetResult && <button className="rounded-lg border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800" onClick={downloadDatasetReport}>Download report</button>}
            </div>
            {datasetError && <p role="alert" className="mt-3 text-sm text-red-300">{datasetError}</p>}
            {datasetValidation && (
              <div className="mt-3 rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-sm">
                <div className={`flex items-center gap-2 font-medium ${datasetValidation.valid ? 'text-emerald-300' : 'text-red-300'}`}>
                  {datasetValidation.valid ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                  {datasetValidation.valid ? 'CSV validated' : 'CSV validation failed'}
                  <span className="text-slate-400">· {String(datasetValidation.row_count)} rows</span>
                </div>
                <p className="mt-1 break-words text-xs text-slate-400">Columns: {(datasetValidation.columns as string[]).join(', ')}</p>
                {(datasetValidation.errors as string[]).map((item) => <p key={item} className="mt-1 text-xs text-red-300">{item}</p>)}
                {(datasetValidation.warnings as string[]).map((item) => <p key={item} className="mt-1 text-xs text-amber-200">{item}</p>)}
              </div>
            )}
            {datasetResult && (
              <div className="mt-3 rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300">
                Analyzed {String(datasetResult.rows_processed)} rows. Report is ready to download.
              </div>
            )}
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="text-lg font-semibold text-white">Model evaluation</h2>
              <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-200">
                {metrics?.evaluation_type ?? 'DEMO'} · {metrics?.dataset_type ?? 'unknown'}
              </span>
            </div>
            <p className="mb-3 text-sm text-slate-400">{metrics?.notes ?? 'Evaluation metadata is unavailable.'}</p>
            <div className="space-y-3">
              {metrics && Object.entries(metrics.results).map(([name, result]) => (
                <div key={name} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                  <div className="mb-2 flex flex-wrap justify-between gap-2 text-sm font-medium text-white">
                    <span>{name.replaceAll('_', ' ')}</span>
                    <span>{result.n_samples} held-out samples</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs text-slate-300 sm:grid-cols-4">
                    <span>Precision: {result.precision.toFixed(3)}</span>
                    <span>Recall: {result.recall.toFixed(3)}</span>
                    <span>F1: {result.f1_score.toFixed(3)}</span>
                    <span>ROC-AUC: {result.roc_auc == null ? 'N/A' : result.roc_auc.toFixed(3)}</span>
                  </div>
                  <p className="mt-2 text-xs text-slate-400">Confusion matrix [benign, malicious]: {JSON.stringify(result.confusion_matrix)}</p>
                </div>
              ))}
              {!metrics?.results || Object.keys(metrics.results).length === 0 ? <p className="text-sm text-slate-500">No saved evaluation metrics.</p> : null}
            </div>
            {metrics?.training_timestamp && <p className="mt-3 text-xs text-slate-500">Trained {new Date(metrics.training_timestamp).toLocaleString()}</p>}
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">
            <h2 className="mb-4 text-lg font-semibold text-white">Settings and recent events</h2>
            <div className="mb-5 grid gap-3 sm:grid-cols-2">
              {(Object.keys(settings) as (keyof DetectionSettings)[]).map((key) => (
                <label key={key} className="text-xs text-slate-400">
                  <span className="mb-1 block">{key.replaceAll('_', ' ')}</span>
                  <input
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
                    type="number"
                    min={0}
                    max={key === 'risk_threshold' ? 100 : 1}
                    step={key === 'risk_threshold' ? 1 : 0.01}
                    value={settings[key]}
                    onChange={(event) => {
                      setSettings((current) => ({ ...current, [key]: Number(event.target.value) }))
                      setSettingsSaved(false)
                    }}
                  />
                </label>
              ))}
            </div>
            <button className="mb-4 rounded-lg border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800" onClick={() => void saveSettings()}>Save detection settings</button>
            {settingsSaved && <span className="ml-3 text-sm text-emerald-300">Settings saved.</span>}
            <div className="space-y-2">
              {events.length === 0 ? <p className="text-sm text-slate-500">No recent analyzed events.</p> : events.map((event, index) => (
                <div key={event.payload?.alert_id ?? `${event.timestamp}-${index}`} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300">
                  <div className="font-medium text-white">{event.payload?.category.replaceAll('_', ' ') ?? event.event_type}</div>
                  <div className="text-xs text-slate-500">{event.timestamp}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>

      {selectedAlert && (
        <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/70 p-4" role="presentation" onClick={() => setSelectedAlert(null)}>
          <section role="dialog" aria-modal="true" aria-label="Alert details" className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl" onClick={(event) => event.stopPropagation()}>
            <div className="mb-4 flex items-start justify-between">
              <div>
                <p className="text-xs uppercase tracking-widest text-cyan-300">{selectedAlert.alert_id}</p>
                <h2 className="mt-1 text-xl font-semibold text-white">{selectedAlert.category.replaceAll('_', ' ')}</h2>
              </div>
              <button aria-label="Close alert details" className="rounded-lg p-2 text-slate-400 hover:bg-slate-800" onClick={() => setSelectedAlert(null)}><X className="h-5 w-5" /></button>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm text-slate-300">
              <div>Severity: <span style={{ color: severityColors[selectedAlert.severity] }}>{selectedAlert.severity}</span></div>
              <div>Risk score: {selectedAlert.risk_score} / 100</div>
              <div>Prediction: {selectedAlert.prediction}</div>
              <div>Model confidence: {selectedAlert.confidence.toFixed(3)} (uncalibrated)</div>
              <div className="col-span-2">Source: {selectedAlert.source_ip} → {selectedAlert.destination_ip}</div>
              <div className="col-span-2">Timestamp: {selectedAlert.timestamp}</div>
            </div>
            <h3 className="mb-2 mt-5 font-medium text-white">Detection reasoning</h3>
            <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
              {selectedAlert.reasons.map((reason) => <li key={reason}>{reason}</li>)}
            </ul>
            {selectedAlert.rule_indicators?.length ? (
              <div className="mt-4 space-y-2">
                {selectedAlert.rule_indicators.map((indicator) => (
                  <div key={indicator.rule_id} className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">
                    {indicator.rule_id} · risk contribution {indicator.weight}
                  </div>
                ))}
              </div>
            ) : null}
          </section>
        </div>
      )}
    </div>
  )
}

export default App
