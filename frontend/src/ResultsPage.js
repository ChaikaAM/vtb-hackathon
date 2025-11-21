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

  const getStatusBadge = (status) => {
    const statusClass = status.toLowerCase();
    const statusLabels = {
      passed: '✅ ПРОЙДЕНО',
      failed: '❌ ПРОВАЛЕНО',
      warning: '⚠️ ПРЕДУПРЕЖДЕНИЕ',
      error: '🔴 ОШИБКА'
    };
    return (
      <span className={`status-badge status-${statusClass}`} style={{
        padding: '4px 12px',
        borderRadius: '4px',
        fontSize: '12px',
        fontWeight: 'bold',
        display: 'inline-block',
        marginLeft: '10px',
        ...(statusClass === 'passed' ? { background: '#4CAF50', color: 'white' } :
            statusClass === 'failed' ? { background: '#f44336', color: 'white' } :
            statusClass === 'warning' ? { background: '#ff9800', color: 'white' } :
            { background: '#9e9e9e', color: 'white' })
      }}>
        {statusLabels[statusClass] || status}
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
          <div className="summary-card" style={{ background: '#2196F3' }}>
            <h3>{result.customCheckResults?.length || 0}</h3>
            <p>Пользовательских проверок</p>
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

        {result.customCheckResults && result.customCheckResults.length > 0 && (
          <div className="custom-checks-section" style={{ marginTop: '30px' }}>
            <h3>🔍 Пользовательские проверки</h3>
            {result.customCheckResults.map((checkResult, idx) => (
              <div 
                key={idx} 
                className={`custom-check-result status-${checkResult.status?.toLowerCase()}`}
                style={{
                  border: '1px solid #ddd',
                  borderRadius: '8px',
                  padding: '20px',
                  marginBottom: '20px',
                  background: checkResult.status === 'PASSED' ? '#f1f8f4' :
                              checkResult.status === 'FAILED' ? '#ffebee' :
                              checkResult.status === 'WARNING' ? '#fff3e0' :
                              '#f5f5f5',
                  color: '#000'
                }}
              >
                <div className="check-result-header" style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between', 
                  alignItems: 'center',
                  marginBottom: '15px'
                }}>
                  <h4 style={{ margin: 0, fontSize: '18px', color: '#000' }}>{checkResult.checkName}</h4>
                  {getStatusBadge(checkResult.status)}
                </div>
                {checkResult.category && (
                  <p style={{ fontSize: '14px', color: '#666', marginBottom: '10px' }}>
                    Категория: {checkResult.category}
                  </p>
                )}
                <div className="check-result-text" style={{ 
                  fontSize: '15px', 
                  lineHeight: '1.6',
                  marginBottom: '15px',
                  whiteSpace: 'pre-wrap',
                  color: '#000'
                }}>
                  {checkResult.result}
                </div>
                {checkResult.vulnerabilities && checkResult.vulnerabilities.length > 0 && (
                  <div className="check-vulnerabilities" style={{ marginTop: '15px' }}>
                    <strong style={{ fontSize: '16px', display: 'block', marginBottom: '10px', color: '#000' }}>
                      Найденные проблемы:
                    </strong>
                    {checkResult.vulnerabilities.map((vuln, vIdx) => (
                      <div 
                        key={vIdx} 
                        className="vulnerability" 
                        style={{
                          borderLeft: '4px solid #f44336',
                          paddingLeft: '15px',
                          marginBottom: '10px',
                          background: '#fff',
                          padding: '10px 15px',
                          borderRadius: '4px',
                          color: '#000'
                        }}
                      >
                        <strong style={{ fontSize: '15px', display: 'block', marginBottom: '5px', color: '#000' }}>
                          {vuln.title}
                        </strong>
                        <p style={{ margin: '5px 0', fontSize: '14px', color: '#000' }}>{vuln.description}</p>
                        {vuln.endpoint && (
                          <p style={{ margin: '5px 0', fontSize: '13px', color: '#666' }}>
                            <strong>Endpoint:</strong> {vuln.method} {vuln.endpoint}
                          </p>
                        )}
                        {vuln.severity && (
                          <span className={`badge ${getSeverityClass(vuln.severity)}`} style={{ marginTop: '5px' }}>
                            {vuln.severity}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                {checkResult.executedAt && (
                  <p style={{ fontSize: '12px', color: '#999', marginTop: '15px', marginBottom: 0 }}>
                    Выполнено: {new Date(checkResult.executedAt).toLocaleString('ru-RU')}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}

        {(!result.vulnerabilities || result.vulnerabilities.length === 0) && 
         (!result.contractMismatches || result.contractMismatches.length === 0) &&
         (!result.customCheckResults || result.customCheckResults.length === 0) && (
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

