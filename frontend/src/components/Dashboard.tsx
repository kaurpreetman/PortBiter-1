"use client";
import React, { useEffect, useRef, useState } from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { VulnerabilityList } from './VulnerabilityList';
import { Vulnerability } from './VulnerabilityCard';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const WS_BASE = API_BASE.startsWith('https') ? API_BASE.replace('https', 'wss') : API_BASE.replace('http', 'ws');

type ScanSummary = {
  scan_id: string;
  target_url: string;
  status: string;
  progress: number;
  vulnerability_count: number;
  started_at: string;
};

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000');
  const [scanId, setScanId] = useState('');
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loadingReport, setLoadingReport] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanSummary[]>([]);
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    loadScanHistory();
  }, []);

  const loadScanHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/scans`);
      if (!res.ok) return;
      const data = await res.json();
      setScanHistory(data);
    } catch (error) {
      console.error(error);
    }
  };

  const loadScan = async (id: string) => {
    try {
      const res = await fetch(`${API_BASE}/scan/${id}`);
      const data = await res.json();
      setScanId(id);
      setStatus(data.status || 'completed');
      setProgress(data.progress || 0);
      setLogs(data.logs || []);
      setVulns(data.vulnerabilities || []);
    } catch (error) {
      console.error(error);
    }
  };

  const downloadPdf = async () => {
    if (!scanId) return;
    setLoadingReport(true);
    try {
      const res = await fetch(`${API_BASE}/report/${scanId}`);
      if (!res.ok) throw new Error('Failed to generate report');

      const payload = await res.json();
      const markdownText = payload.markdown || 'No report content';
      const container = document.createElement('div');
      container.style.width = '794px';
      container.style.padding = '32px';
      container.style.background = '#ffffff';
      container.style.color = '#111827';
      container.style.fontFamily = 'Arial, sans-serif';

      const pre = document.createElement('pre');
      pre.style.whiteSpace = 'pre-wrap';
      pre.style.fontFamily = 'Arial, sans-serif';
      pre.textContent = markdownText;
      container.appendChild(pre);
      document.body.appendChild(container);

      const html2pdfModule = (await import('html2pdf.js')).default;
      await html2pdfModule().set({
        margin: 10,
        filename: `PortBiter_Report_${scanId}.pdf`,
        html2canvas: { scale: 2 },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
      }).from(container).save();

      document.body.removeChild(container);
    } catch (error) {
      console.error(error);
      alert('Error generating PDF report.');
    }
    setLoadingReport(false);
  };

  const startScan = async () => {
    setLogs(['🚀 Starting scan...']);
    setVulns([]);
    setProgress(0);
    setStatus('starting');

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: targetUrl }),
      });

      const data = await res.json();
      if (data.scan_id) {
        setScanId(data.scan_id);
        connectWs(data.scan_id);
        await loadScanHistory();
      }
    } catch (error) {
      console.error(error);
      setStatus('error');
    }
  };

  const connectWs = (id: string) => {
    if (ws.current) {
      ws.current.close();
    }

    ws.current = new WebSocket(`${WS_BASE}/ws/${id}`);

    ws.current.onopen = () => setStatus('running');

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setProgress(data.progress);
      setStatus(data.status);

      if (data.new_logs?.length) {
        setLogs((prev) => [...prev, ...data.new_logs]);
      }

      if (data.vulnerabilities) {
        setVulns(data.vulnerabilities);
      }

      if (data.status === 'completed' || data.status === 'error') {
        loadScanHistory();
      }
    };

    ws.current.onclose = () => setStatus('completed');
  };

  const severityChartData = Object.entries(
    vulns.reduce((acc, vuln) => {
      const severity = (vuln.severity || 'LOW').toUpperCase();
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
  ).map(([name, value]) => ({ name, value }));

  return (
    <div className="min-h-screen bg-gray-950 text-green-400 font-mono p-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center gap-3 border-b border-green-800 pb-4">
          <img src="/logo.png" alt="PortBiter Logo" className="w-20 h-20 object-contain" />
          <div>
            <h1 className="text-3xl font-bold text-white">PortBiter</h1>
            <span className="text-sm text-gray-400">AI-Powered Web Vulnerability Scanner</span>
          </div>
        </div>

        <div className="flex gap-4">
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 bg-gray-900 border border-green-800 p-3 rounded focus:outline-none focus:border-green-400 text-white"
            placeholder="Enter target URL"
            disabled={status === 'running'}
          />
          <button
            onClick={startScan}
            disabled={status === 'running'}
            className="bg-green-600 hover:bg-green-500 text-black px-6 py-3 rounded font-bold uppercase transition"
          >
            {status === 'running' ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>

        {status !== 'idle' && (
          <div className="bg-gray-900 border border-green-800 p-4 rounded">
            <div className="flex flex-col gap-2 mb-2 text-sm sm:flex-row sm:items-center sm:justify-between">
              <div>
                <span>
                  Status: <span className="text-white uppercase">{status}</span>
                </span>
                {scanId && <span className="ml-3 text-gray-400">Scan ID: {scanId}</span>}
              </div>
              <span>{progress}%</span>
            </div>
            <div className="w-full bg-gray-800 h-2 rounded overflow-hidden">
              <div className="bg-green-500 h-full transition-all duration-500" style={{ width: `${progress}%` }} />
            </div>
            {status === 'error' && (
              <div className="mt-3 text-red-400 text-sm">
                Scan failed. Please review the logs and try again with a valid target.
              </div>
            )}
          </div>
        )}

        {vulns.length > 0 && (
          <div className="bg-gray-900 border border-green-800 rounded p-4">
            <h3 className="text-white mb-3">📊 Severity Breakdown</h3>
            <div className="h-64">
              <PieChart width={500} height={220}>
                <Pie data={severityChartData} dataKey="value" nameKey="name" outerRadius={80} fill="#10b981">
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={['#dc2626', '#ea580c', '#ca8a04', '#16a34a'][index % 4]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-black border border-green-800 rounded p-4 h-96 overflow-y-auto text-xs">
            <h3 className="text-white mb-3 border-b border-green-800 pb-2">🖥️ Live Scan Logs</h3>
            {logs.map((log, index) => (
              <div key={`${log}-${index}`} className="text-green-400 mb-1">
                <span className="text-green-600 mr-2">❯</span>
                {log}
              </div>
            ))}
          </div>

          <div className="bg-gray-900 border border-red-800 rounded p-4 h-[500px] overflow-y-auto">
            <h3 className="text-white mb-3 border-b border-red-800 pb-2">🐞 Vulnerabilities Found</h3>
            {vulns.length === 0 ? (
              <p className="text-gray-500 text-sm">No vulnerabilities detected yet...</p>
            ) : (
              <VulnerabilityList vulnerabilities={vulns} />
            )}
          </div>
        </div>

        {scanHistory.length > 0 && (
          <div className="bg-gray-900 border border-green-800 rounded p-4">
            <h3 className="text-white mb-3">🗂️ Scan History</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm text-left text-gray-300">
                <thead className="text-xs uppercase text-gray-500">
                  <tr>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Findings</th>
                    <th className="px-3 py-2">Started At</th>
                    <th className="px-3 py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {scanHistory.map((scan) => (
                    <tr key={scan.scan_id} className="border-t border-gray-800">
                      <td className="px-3 py-2 text-white">{scan.target_url}</td>
                      <td className="px-3 py-2 uppercase">{scan.status}</td>
                      <td className="px-3 py-2">{scan.vulnerability_count}</td>
                      <td className="px-3 py-2">{scan.started_at}</td>
                      <td className="px-3 py-2">
                        <button onClick={() => loadScan(scan.scan_id)} className="text-green-400 hover:text-green-300">
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {status === 'completed' && (
          <div className="bg-gray-900 border border-green-800 p-6 rounded">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-xl text-white font-bold">📄 Security Report</h3>
                <p className="text-gray-400 text-sm">HTML-rendered report export</p>
              </div>
              <button
                onClick={downloadPdf}
                disabled={loadingReport}
                className="bg-red-600 hover:bg-red-500 text-white px-6 py-3 rounded font-bold flex items-center gap-2"
              >
                {loadingReport ? 'Generating...' : 'Download PDF'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}