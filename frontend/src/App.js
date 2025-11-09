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
                    options: options
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
