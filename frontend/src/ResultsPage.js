import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import './App.css';
import './ResultsPage.css';

function ResultsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchResult();
  }, [scanId]);

  const fetchResult = async () => {
    try {
      const response = await fetch(`/api/analysis/history/${scanId}/status`);
      if (!response.ok) {
        throw new Error('Failed to fetch result');
      }
      const data = await response.json();
      setResult(data);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const downloadReport = async (format) => {
    const formatMap = {
      html: 'HTML',
      json: 'JSON_EXTENDED',
      pdf: 'PDF'
    };
    
    const reportType = formatMap[format];
    const url = `/api/reports/${scanId}/${reportType}`;
    
    try {
      if (format === 'pdf') {
        // For PDF, we need to fetch as blob and create download link
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error('Failed to download PDF');
        }
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `report-${scanId}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(downloadUrl);
      } else {
        // For HTML and JSON, use window.open
        window.open(url, '_blank');
      }
    } catch (error) {
      console.error('Error downloading report:', error);
      alert('Ошибка при скачивании отчета: ' + error.message);
    }
  };

  const getSeverityClass = (severity) => {
    const severityMap = {
      CRITICAL: 'severity-critical',
      HIGH: 'severity-high',
      MEDIUM: 'severity-medium',
      LOW: 'severity-low',
      INFO: 'severity-info'
    };
    return severityMap[severity] || 'severity-info';
  };

  const getSeverityBadge = (severity) => {
    return (
      <span className={`badge ${getSeverityClass(severity)}`}>
        {severity}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="results-page">
        <div className="loading">Загрузка результатов...</div>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="results-page">
        <div className="error-message">
          <h2>Ошибка</h2>
          <p>{error || 'Результаты не найдены'}</p>
          <button onClick={() => navigate('/')} className="btn-back">
            Вернуться на главную
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="results-page">
      <div className="results-header">
        <button onClick={() => navigate('/')} className="btn-back">
          ← Назад к списку
        </button>
        <div className="download-buttons">
          <button onClick={() => downloadReport('html')} className="btn-download">
            📄 Скачать HTML
          </button>
          <button onClick={() => downloadReport('json')} className="btn-download">
            📄 Скачать JSON
          </button>
          <button onClick={() => downloadReport('pdf')} className="btn-download">
            📄 Скачать PDF
          </button>
        </div>
      </div>

      <div className="results-section">
        <h2>📊 Результаты анализа</h2>
        
        <div className="summary-cards">
          <div className="summary-card">
            <h3>{result.totalEndpoints || 0}</h3>
            <p>Эндпоинтов</p>
          </div>
          <div className="summary-card critical">
            <h3>{result.vulnerabilities?.length || 0}</h3>
            <p>Уязвимостей</p>
          </div>
          <div className="summary-card warning">
            <h3>{result.contractMismatches?.length || 0}</h3>
            <p>Несоответствий контракту</p>
          </div>
          <div className="summary-card">
            <h3>{result.durationMs ? (result.durationMs / 1000).toFixed(1) + 's' : '-'}</h3>
            <p>Время анализа</p>
          </div>
        </div>

        {result.summary && (
          <div className="summary-box">
            <p>{result.summary}</p>
          </div>
        )}

        {result.vulnerabilities && result.vulnerabilities.length > 0 && (
          <div className="vulnerabilities-section">
            <h3>🔴 Обнаруженные уязвимости</h3>
            {result.vulnerabilities.map((vuln, idx) => (
              <div key={idx} className={`vulnerability ${getSeverityClass(vuln.severity)}`}>
                <div className="vuln-header">
                  {getSeverityBadge(vuln.severity)}
                  <span className="owasp-badge">{vuln.owaspCategory}</span>
                  <h4>{vuln.title}</h4>
                </div>
                <p className="vuln-description">{vuln.description}</p>
                {vuln.endpoint && (
                  <p className="vuln-endpoint">
                    <strong>Endpoint:</strong> {vuln.method} {vuln.endpoint}
                  </p>
                )}
                {vuln.evidence && (
                  <p className="vuln-evidence">
                    <strong>Доказательство:</strong> {vuln.evidence}
                  </p>
                )}
                {vuln.recommendation && (
                  <div className="recommendation">
                    <strong>💡 Рекомендация:</strong>
                    <p>{vuln.recommendation}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {result.contractMismatches && result.contractMismatches.length > 0 && (
          <div className="mismatches-section">
            <h3>⚠️ Несоответствия контракту</h3>
            <table className="mismatches-table">
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Method</th>
                  <th>Type</th>
                  <th>Expected</th>
                  <th>Actual</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {result.contractMismatches.map((mismatch, idx) => (
                  <tr key={idx}>
                    <td>{mismatch.endpoint}</td>
                    <td>{mismatch.method}</td>
                    <td>{mismatch.type}</td>
                    <td>{mismatch.expected}</td>
                    <td>{mismatch.actual}</td>
                    <td>{mismatch.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {(!result.vulnerabilities || result.vulnerabilities.length === 0) && 
         (!result.contractMismatches || result.contractMismatches.length === 0) && (
          <div className="no-issues">
            <h3>✅ Проблем не найдено!</h3>
            <p>API соответствует спецификации и не содержит явных уязвимостей.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default ResultsPage;

