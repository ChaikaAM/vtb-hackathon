# VTB Hackathon - API Security Analyzer

**Пожалуйста, не стесняйтесь тестировать решение по адресу https://vtb.seag.pro**  
**Так же с примером интеграции в CI/CD пайплайн можно ознакомиться по ссылке https://jenkins.seag.pro (admin:admin12345678)**

Инструмент объединяет **статический анализ**, **динамическое тестирование** и **валидацию контракта** в одном решении.

##  Возможности

- **Статический анализ** - анализ OpenAPI спецификаций
- **Динамическое тестирование** - тестирование реального API на уязвимости
- **Валидация контракта** - сравнение поведения API с спецификацией
- **Интеграция с ИИ** - анализ и фильтрация уязвимостей с помощью AI агента
- **Покрытие OWASP API Top 10 2023**
- **Генерация отчетов** - HTML, JSON, PDF

##  Быстрый старт

### Backend (Java 17+)

```bash
cd backend
./mvnw clean install
./mvnw spring-boot:run
```

Backend будет доступен: `http://localhost:8080/api`

### Frontend (Node.js)

```bash
cd frontend
npm install
npm start
```

Frontend будет доступен: `http://localhost:3000`

## OWASP API Top 10 2023 Покрытие

| OWASP Category | Статический анализ | Динамическое тестирование | Статус |
|----------------|-------------------|--------------------------|--------|
| API1:2023 - Broken Object Level Authorization | ✅ | ✅ BOLA/IDOR тесты | ✅ |
| API2:2023 - Broken Authentication | ✅ | ✅ Тесты токенов | ✅ |
| API3:2023 - Broken Property Level Authorization | ✅ | ✅ Mass assignment | ✅ |
| API4:2023 - Unrestricted Resource Consumption | ✅ | ✅ Rate limiting тесты | ✅ |
| API5:2023 - Broken Function Level Authorization | ✅ | - | ✅ |
| API6:2023 - Unrestricted Business Flows | ✅ | ✅ Automation тесты | ✅ |
| API7:2023 - Server Side Request Forgery | ✅ | - | ✅ |
| API8:2023 - Security Misconfiguration | ✅ | ✅ Injection тесты | ✅ |
| API9:2023 - Improper Inventory Management | ✅ | - | ✅ |
| API10:2023 - Unsafe Consumption of APIs | ✅ | ✅ Third-party data тесты | ✅ |

**Полное покрытие: 100% (10/10)** 

## 🛠️ Технологический стек

### Backend
- Java 17+
- Spring Boot 3.2
- Swagger Parser 2.1 (OpenAPI парсинг)
- OkHttp 4.12 (HTTP клиент)
- JSONPath (работа с JSON)
- Everit JSON Schema (валидация схем)
- Thymeleaf (HTML отчеты)

### Frontend
- React 18
- Modern CSS

### Docker Compose

```bash
cd backend
docker-compose up -d
```

## 📝 Примеры использования

### Анализ через UI

1. Откройте http://localhost:3000
2. Выберите предустановленный API или введите свой
3. Нажмите "Запустить анализ"
4. Просмотрите результаты

### Анализ через curl

```bash
curl -X POST http://localhost:8080/api/analysis/scan \
  -H "Content-Type: application/json" \
  -d '{
    "openApiUrl": "https://vbank.open.bankingapi.ru/openapi.json",
    "apiBaseUrl": "https://vbank.open.bankingapi.ru"
  }'
```