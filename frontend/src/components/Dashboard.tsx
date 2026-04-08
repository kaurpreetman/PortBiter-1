"use client";
import React, { useState, useRef } from 'react';
import { VulnerabilityList } from './VulnerabilityList';
import { Vulnerability } from './VulnerabilityCard';

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState("http://example.com");
  const [scanId, setScanId] = useState("");
  const [status, setStatus] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loadingReport, setLoadingReport] = useState(false);
  const ws = useRef<WebSocket | null>(null);

  const downloadPdf = async () => {
    setLoadingReport(true);
    try {
      const res = await fetch(`http://localhost:8000/report/pdf/${scanId}`);
      if (!res.ok) throw new Error("Failed to generate PDF");

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `PortBiter_Report_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
      alert("Error generating PDF report.");
    }
    setLoadingReport(false);
  };

  const startScan = async () => {
    setLogs(["🚀 Starting scan..."]);
    setVulns([]);
    setProgress(0);
    setStatus("starting");

    try {
      const res = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl })
      });

      const data = await res.json();
      if (data.scan_id) {
        setScanId(data.scan_id);
        connectWs(data.scan_id);
      }
    } catch (e) {
      console.error(e);
      setStatus("error");
    }
  };

  const connectWs = (id: string) => {
    ws.current = new WebSocket(`ws://localhost:8000/ws/${id}`);

    ws.current.onopen = () => setStatus("running");

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);

      setProgress(data.progress);
      setStatus(data.status);

      if (data.new_logs?.length) {
        setLogs(prev => [...prev, ...data.new_logs]);
      }

      if (data.vulnerabilities) {
        setVulns(data.vulnerabilities);
      }
    };

    ws.current.onclose = () => setStatus("completed");
  };

  return (
    <div className="min-h-screen bg-gray-950 text-green-400 font-mono p-8">
      <div className="max-w-6xl mx-auto space-y-6">

        {/* 🔥 HEADER WITH LOGO */}
        <div className="flex items-center gap-3 border-b border-green-800 pb-4">
          <img 
            src="/logo.png" 
            alt="PortBiter Logo" 
            className="w-20 h-20 object-contain"
          />

          <div>
            <h1 className="text-3xl font-bold text-white">
              PortBiter
            </h1>
            <span className="text-sm text-gray-400">
              AI-Powered Web Vulnerability Scanner
            </span>
          </div>
        </div>

        {/* 🔍 INPUT */}
        <div className="flex gap-4">
          <input 
            type="text" 
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 bg-gray-900 border border-green-800 p-3 rounded focus:outline-none focus:border-green-400 text-white"
            placeholder="Enter target URL"
            disabled={status === "running"}
          />
          <button 
            onClick={startScan}
            disabled={status === "running"}
            className="bg-green-600 hover:bg-green-500 text-black px-6 py-3 rounded font-bold uppercase transition"
          >
            {status === "running" ? "Scanning..." : "Start Scan"}
          </button>
        </div>

        {/* 📊 STATUS */}
        {status !== "idle" && (
          <div className="bg-gray-900 border border-green-800 p-4 rounded">
            <div className="flex justify-between mb-2 text-sm">
              <span>Status: <span className="text-white uppercase">{status}</span></span>
              <span>{progress}%</span>
            </div>
            <div className="w-full bg-gray-800 h-2 rounded overflow-hidden">
              <div 
                className="bg-green-500 h-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* 🧠 MAIN GRID */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

          {/* 🖥️ TERMINAL */}
          <div className="bg-black border border-green-800 rounded p-4 h-96 overflow-y-auto text-xs">
            <h3 className="text-white mb-3 border-b border-green-800 pb-2">
              🖥️ Live Scan Logs
            </h3>
            {logs.map((log, i) => (
              <div key={i} className="text-green-400 mb-1">
                <span className="text-green-600 mr-2">❯</span>{log}
              </div>
            ))}
          </div>

          {/* 🐞 VULNERABILITIES */}
          <div className="bg-gray-900 border border-red-800 rounded p-4 h-[500px] overflow-y-auto">
            <h3 className="text-white mb-3 border-b border-red-800 pb-2">
              🐞 Vulnerabilities Found
            </h3>

            {vulns.length === 0 ? (
              <p className="text-gray-500 text-sm">
                No vulnerabilities detected yet...
              </p>
            ) : (
              <VulnerabilityList vulnerabilities={vulns} />
            )}
          </div>
        </div>

        {/* 📄 REPORT */}
        {status === "completed" && (
          <div className="bg-gray-900 border border-green-800 p-6 rounded">
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-xl text-white font-bold">
                  📄 Security Report
                </h3>
                <p className="text-gray-400 text-sm">
                  AI-generated concise audit report
                </p>
              </div>

              <button 
                onClick={downloadPdf}
                disabled={loadingReport}
                className="bg-red-600 hover:bg-red-500 text-white px-6 py-3 rounded font-bold flex items-center gap-2"
              >
                {loadingReport ? "Generating..." : "Download PDF"}
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}