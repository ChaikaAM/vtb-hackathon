import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate } from 'react-router-dom';
import ScanHistoryTable from './ScanHistoryTable';
import ResultsPage from './ResultsPage';
import './App.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/results/:scanId" element={<ResultsPage />} />
      </Routes>
    </Router>
  );
}

function HomePage() {
  const navigate = useNavigate();
  const [openApiUrl, setOpenApiUrl] = useState('');
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [options, setOptions] = useState({
    enableStaticAnalysis: true,
    enableDynamicTesting: true,
    enableContractValidation: true,
    enableAiAnalysis: true
  });
  const [customChecks, setCustomChecks] = useState([]);

  const apiEndpoints = [
    {
      name: 'VBank API',
      openApiUrl: 'https://vbank.open.bankingapi.ru/openapi.json',
      apiBaseUrl: 'https://vbank.open.bankingapi.ru'
    },
    {
      name: 'ABank API',
      openApiUrl: 'https://abank.open.bankingapi.ru/openapi.json',
      apiBaseUrl: 'https://abank.open.bankingapi.ru'
    },
    {
      name: 'SBank API',
      openApiUrl: 'https://sbank.open.bankingapi.ru/openapi.json',
      apiBaseUrl: 'https://sbank.open.bankingapi.ru'
    }
  ];

  const handlePreset = (preset) => {
    setOpenApiUrl(preset.openApiUrl);
    setApiBaseUrl(preset.apiBaseUrl);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/analysis/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          openApiUrl,
          apiBaseUrl,
          authToken: authToken || null,
          options: {
            ...options,
            customChecks: customChecks.filter(check => 
              check.enabled && check.name && check.prompt && 
              check.name.trim() && check.prompt.trim()
            )
          }
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Анализ не удался');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleViewResult = (scanId) => {
    navigate(`/results/${scanId}`);
  };

  const addCustomCheck = () => {
    const newCheck = {
      id: Date.now().toString(),
      name: '',
      prompt: '',
      description: '',
      category: 'Общая',
      enabled: true
    };
    setCustomChecks([...customChecks, newCheck]);
  };

  const removeCustomCheck = (id) => {
    setCustomChecks(customChecks.filter(check => check.id !== id));
  };

  const updateCustomCheck = (id, field, value) => {
    setCustomChecks(customChecks.map(check => 
      check.id === id ? { ...check, [field]: value } : check
    ));
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🔒 API Security Analyzer</h1>
        <p>Автоматический анализ уязвимостей API - VTB Hackathon</p>
      </header>

      <main className="container">
        <section className="analysis-form">
          <h2>Запустить анализ</h2>
          
          <div className="presets">
            <h3>Быстрый выбор:</h3>
            {apiEndpoints.map((preset, idx) => (
              <button 
                key={idx} 
                onClick={() => handlePreset(preset)}
                className="preset-btn"
              >
                {preset.name}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>OpenAPI Specification URL:</label>
              <input
                type="text"
                value={openApiUrl}
                onChange={(e) => setOpenApiUrl(e.target.value)}
                placeholder="https://api.example.com/openapi.json"
                required
              />
            </div>

            <div className="form-group">
              <label>API Base URL:</label>
              <input
                type="text"
                value={apiBaseUrl}
                onChange={(e) => setApiBaseUrl(e.target.value)}
                placeholder="https://api.example.com"
                required
              />
            </div>

            <div className="form-group">
              <button
                type="button"
                onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
                className="advanced-toggle-btn"
                style={{
                  background: 'transparent',
                  border: '1px solid #ccc',
                  borderRadius: '4px',
                  padding: '8px 16px',
                  cursor: 'pointer',
                  color: '#666',
                  fontSize: '14px',
                  width: '100%'
                }}
              >
                {showAdvancedOptions ? '▼' : '▶'} Дополнительные настройки
              </button>
              
              {showAdvancedOptions && (
                <>
                  <div className="form-group" style={{ marginTop: '15px' }}>
                    <label>Authentication Token (опционально):</label>
                    <input
                      type="password"
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder="Bearer token для авторизации"
                    />
                  </div>
                  
                  <div className="analysis-settings">
                    <h4>Настройки анализа:</h4>
                    
                    <div className="checkbox-group">
                      <label className="checkbox-container">
                        <input
                          type="checkbox"
                          checked={options.enableStaticAnalysis}
                          onChange={(e) => setOptions({...options, enableStaticAnalysis: e.target.checked})}
                        />
                        <span className="checkbox-custom"></span>
                        <span className="checkbox-label">Статический анализ</span>
                      </label>
                      
                      <label className="checkbox-container">
                        <input
                          type="checkbox"
                          checked={options.enableDynamicTesting}
                          onChange={(e) => setOptions({...options, enableDynamicTesting: e.target.checked})}
                        />
                        <span className="checkbox-custom"></span>
                        <span className="checkbox-label">Динамическое тестирование</span>
                      </label>
                      
                      <label className="checkbox-container">
                        <input
                          type="checkbox"
                          checked={options.enableContractValidation}
                          onChange={(e) => setOptions({...options, enableContractValidation: e.target.checked})}
                        />
                        <span className="checkbox-custom"></span>
                        <span className="checkbox-label">Валидация контракта</span>
                      </label>
                      
                      <label className="checkbox-container">
                        <input
                          type="checkbox"
                          checked={options.enableAiAnalysis}
                          onChange={(e) => setOptions({...options, enableAiAnalysis: e.target.checked})}
                        />
                        <span className="checkbox-custom"></span>
                        <span className="checkbox-label">AI анализ</span>
                      </label>
                    </div>
                  </div>
                  
                  <div className="custom-checks-section" style={{ marginTop: '20px' }}>
                    <h4>Пользовательские проверки:</h4>
                    <p style={{ fontSize: '14px', color: '#666', marginBottom: '10px' }}>
                      Добавьте свои проверки, которые будут выполнены с помощью AI
                    </p>
                    <button 
                      type="button" 
                      onClick={addCustomCheck}
                      className="btn-add-check"
                      style={{
                        background: '#4CAF50',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        padding: '8px 16px',
                        cursor: 'pointer',
                        fontSize: '14px',
                        marginBottom: '15px'
                      }}
                    >
                      + Добавить проверку
                    </button>
                    
                    {customChecks.map((check, idx) => (
                      <div key={check.id} className="custom-check-item" style={{
                        border: '1px solid #ddd',
                        borderRadius: '4px',
                        padding: '15px',
                        marginBottom: '15px',
                        background: '#f9f9f9'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                          <input
                            type="text"
                            placeholder="Название проверки"
                            value={check.name}
                            onChange={(e) => updateCustomCheck(check.id, 'name', e.target.value)}
                            style={{
                              flex: 1,
                              padding: '8px',
                              border: '1px solid #ccc',
                              borderRadius: '4px',
                              fontSize: '14px',
                              marginRight: '10px'
                            }}
                          />
                          <button 
                            type="button" 
                            onClick={() => removeCustomCheck(check.id)}
                            style={{
                              background: '#f44336',
                              color: 'white',
                              border: 'none',
                              borderRadius: '4px',
                              padding: '8px 12px',
                              cursor: 'pointer',
                              fontSize: '16px'
                            }}
                          >
                            ✕
                          </button>
                        </div>
                        <textarea
                          placeholder="Опишите проверку, которую нужно выполнить (промпт для AI)... Например: 'Проверь, что все endpoints, работающие с персональными данными, требуют аутентификации'"
                          value={check.prompt}
                          onChange={(e) => updateCustomCheck(check.id, 'prompt', e.target.value)}
                          rows={4}
                          style={{
                            width: '100%',
                            padding: '8px',
                            border: '1px solid #ccc',
                            borderRadius: '4px',
                            fontSize: '14px',
                            fontFamily: 'inherit',
                            marginBottom: '10px',
                            resize: 'vertical'
                          }}
                        />
                        <label className="checkbox-container">
                          <input
                            type="checkbox"
                            checked={check.enabled}
                            onChange={(e) => updateCustomCheck(check.id, 'enabled', e.target.checked)}
                          />
                          <span className="checkbox-custom"></span>
                          <span className="checkbox-label">Включить проверку</span>
                        </label>
                      </div>
                    ))}
                    
                    {customChecks.length === 0 && (
                      <p style={{ fontSize: '14px', color: '#999', fontStyle: 'italic', marginTop: '10px' }}>
                        Пока нет пользовательских проверок. Нажмите "Добавить проверку" для создания новой.
                      </p>
                    )}
                  </div>
                </>
              )}
            </div>

            <button type="submit" disabled={loading} className="submit-btn">
              {loading ? '⏳ Анализ...' : '🚀 Запустить анализ'}
            </button>
          </form>
        </section>

        {error && (
          <section className="error-section">
            <h2>❌ Ошибка</h2>
            <p>{error}</p>
          </section>
        )}

        <ScanHistoryTable onViewResult={handleViewResult} />
      </main>

      <footer className="App-footer">
        <p>VTB Hackathon 2025 - API Security Analyzer</p>
        <p>Based on OWASP API Security Top 10 2023</p>
      </footer>
    </div>
  );
}

export default App;
