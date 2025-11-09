import React, { useState, useEffect } from 'react';
import './ScanHistoryTable.css';

function ScanHistoryTable({ onViewResult }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 2000); // Обновление каждые 2 секунды
    return () => clearInterval(interval);
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await fetch('/api/analysis/history');
      if (!response.ok) {
        throw new Error('Failed to fetch history');
      }
      const data = await response.json();
      setHistory(data);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const handleCancel = async (scanId) => {
    try {
      const response = await fetch(`/api/analysis/history/${scanId}/cancel`, {
        method: 'POST'
      });
      if (response.ok) {
        fetchHistory();
      }
    } catch (err) {
      alert('Ошибка при остановке анализа: ' + err.message);
    }
  };

  const handleDelete = async (scanId) => {
    if (!window.confirm('Вы уверены, что хотите удалить этот анализ?')) {
      return;
    }
    try {
      const response = await fetch(`/api/analysis/history/${scanId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        fetchHistory();
      }
    } catch (err) {
      alert('Ошибка при удалении: ' + err.message);
    }
  };

  const handleDownloadPdf = async (scanId) => {
    const url = `/api/reports/${scanId}/PDF`;
    try {
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
    } catch (error) {
      console.error('Error downloading PDF:', error);
      alert('Ошибка при скачивании PDF: ' + error.message);
    }
  };

  const formatDuration = (ms) => {
    if (!ms || ms < 0) return '0с';
    
    const totalSeconds = Math.floor(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    
    if (minutes > 0) {
      return `${minutes}м ${seconds}с`;
    } else {
      return `${seconds}с`;
    }
  };

  const formatDateTime = (dateTime) => {
    if (!dateTime) return '-';
    const date = new Date(dateTime);
    return date.toLocaleString('ru-RU', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const getStatusBadge = (status) => {
    const statusMap = {
      RUNNING: { class: 'status-running', text: 'Выполняется' },
      COMPLETED: { class: 'status-completed', text: 'Завершен' },
      FAILED: { class: 'status-failed', text: 'Ошибка' },
      CANCELLED: { class: 'status-cancelled', text: 'Отменен' },
      PENDING: { class: 'status-pending', text: 'Ожидание' }
    };
    const statusInfo = statusMap[status] || { class: 'status-unknown', text: status };
    return <span className={`status-badge ${statusInfo.class}`}>{statusInfo.text}</span>;
  };

  if (loading) {
    return <div className="history-loading">Загрузка истории...</div>;
  }

  if (error) {
    return <div className="history-error">Ошибка: {error}</div>;
  }

  if (history.length === 0) {
    return <div className="history-empty">История запусков пуста</div>;
  }

  return (
    <div className="scan-history-table">
      <h2>История запусков анализа</h2>
      <table>
        <thead>
          <tr>
            <th>Время начала</th>
            <th>Банк</th>
            <th>Описание</th>
            <th>Статус</th>
            <th>Длительность</th>
            <th>Действия</th>
          </tr>
        </thead>
        <tbody>
          {history.map((item) => {
            // Calculate description
            let description = item.description;
            if (!description) {
              const parts = [];
              if (item.bankName) parts.push(item.bankName);
              const opts = [];
              if (item.options?.enableStaticAnalysis) opts.push('Статический анализ');
              if (item.options?.enableDynamicTesting) opts.push('Динамическое тестирование');
              if (item.options?.enableContractValidation) opts.push('Валидация контракта');
              if (item.options?.enableAiAnalysis) opts.push('AI анализ');
              if (opts.length > 0) {
                parts.push(opts.join(', '));
              } else {
                parts.push('Базовый анализ');
              }
              description = parts.join(' - ');
            }
            
            // Calculate duration for completed scans
            let duration = item.durationMs || 0;
            // Для выполняющихся анализов длительность рассчитывается в DurationTimer
            
            return (
              <tr key={item.scanId}>
                <td>{formatDateTime(item.startTime)}</td>
                <td>{item.bankName || '-'}</td>
                <td>{description}</td>
                <td>{getStatusBadge(item.status)}</td>
                <td className="duration-cell">
                  {item.status === 'RUNNING' ? (
                    <DurationTimer initialDurationMs={item.durationMs} />
                  ) : (
                    formatDuration(duration)
                  )}
                </td>
                <td className="actions-cell">
                  {item.status === 'COMPLETED' && (
                    <>
                      <button 
                        className="btn-view"
                        onClick={() => onViewResult(item.scanId)}
                      >
                        Просмотр
                      </button>
                      <button 
                        className="btn-download"
                        onClick={() => window.open(`/api/reports/${item.scanId}/HTML`, '_blank')}
                        title="Скачать HTML"
                      >
                        📄 HTML
                      </button>
                      <button 
                        className="btn-download"
                        onClick={() => window.open(`/api/reports/${item.scanId}/JSON_EXTENDED`, '_blank')}
                        title="Скачать JSON"
                      >
                        📄 JSON
                      </button>
                      <button 
                        className="btn-download"
                        onClick={() => handleDownloadPdf(item.scanId)}
                        title="Скачать PDF"
                      >
                        📄 PDF
                      </button>
                    </>
                  )}
                  {item.status === 'RUNNING' && (
                    <button 
                      className="btn-cancel"
                      onClick={() => handleCancel(item.scanId)}
                    >
                      Остановить
                    </button>
                  )}
                  <button 
                    className="btn-delete"
                    onClick={() => handleDelete(item.scanId)}
                    title="Удалить"
                  >
                    🗑️
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DurationTimer({ initialDurationMs }) {
  const [duration, setDuration] = useState(initialDurationMs || 0);
  const [startTimestamp] = useState(Date.now());

  useEffect(() => {
    // Используем начальную длительность с сервера (она правильная)
    // и добавляем секунды с момента монтирования компонента
    const updateDuration = () => {
      const elapsed = Date.now() - startTimestamp;
      setDuration((initialDurationMs || 0) + elapsed);
    };
    
    updateDuration();
    const interval = setInterval(updateDuration, 1000);
    return () => clearInterval(interval);
  }, [initialDurationMs, startTimestamp]);

  const formatDuration = (ms) => {
    if (!ms || ms < 0) return '0с';
    
    const totalSeconds = Math.floor(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    
    if (minutes > 0) {
      return `${minutes}м ${seconds}с`;
    } else {
      return `${seconds}с`;
    }
  };

  return <span className="duration-timer">{formatDuration(duration)}</span>;
}

export default ScanHistoryTable;

