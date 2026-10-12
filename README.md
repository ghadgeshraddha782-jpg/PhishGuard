# 🛡️ PhishGuard
### Phishing Email Detection & Awareness Dashboard

PhishGuard is a machine learning-based application designed to analyze emails, identify potential phishing threats, and help users understand suspicious email characteristics through a dashboard.

## 🚀 Features

- **Email Analysis:** Analyze email content to identify potential phishing threats.
- **Machine Learning Detection:** Uses a trained Random Forest model for phishing-related prediction.
- **URL Analysis:** Examines URLs for suspicious characteristics.
- **Sender Analysis:** Evaluates sender-related information for potential warning signs.
- **Attachment Analysis:** Supports attachment-related security analysis.
- **Risk Assessment:** Provides risk-related insights based on analysis results.
- **User Authentication:** Supports user registration and login.
- **Dashboard:** Displays email analysis information and relevant statistics.
- **Security Awareness:** Helps users recognize potential phishing indicators.

## 🧰 Tech Stack

| Component | Technologies |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn, Random Forest |
| Data Processing | Pandas, NumPy |
| Database | SQLite |
| API Testing | FastAPI Swagger UI |
| Version Control | Git, GitHub |

## 📂 Project Structure

```text
PhishGuard/
├── backend/
│   ├── routes/
│   ├── services/
│   ├── utils/
│   ├── app.py
│   ├── auth_routes.py
│   └── database.py
├── data/
│   ├── generate_dataset.py
│   ├── generate_features.py
│   ├── phishing_email_dataset.csv
│   └── phishing_email_features.csv
├── frontend/
│   ├── public/
│   └── src/
├── ml/
│   ├── evaluation.py
│   ├── predict.py
│   └── train_model.py
├── models/
│   └── random_forest_model.pkl
├── requirements.txt
└── README.md
```

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.10 or a compatible version
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone https://github.com/ghadgeshraddha782-jpg/PhishGuard.git
cd PhishGuard
```

### 2. Set up the Python backend

Create and activate a virtual environment.

**Windows:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the backend server:

```bash
python -m uvicorn backend.app:app --reload
```

Backend API:

`http://127.0.0.1:8000`

Interactive API documentation:

`http://127.0.0.1:8000/docs`

### 3. Set up the frontend

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL displayed by Vite, usually:

`http://localhost:5173`

## 🧠 Machine Learning Workflow

1. Prepare and process the email dataset.
2. Extract relevant features for analysis.
3. Train the Random Forest classification model.
4. Use the trained model for prediction.
5. Present analysis and risk-related information through the dashboard.

## 🎯 Project Objective

The objective of PhishGuard is to support phishing threat identification and improve security awareness by combining machine learning, email analysis, and a user-friendly web interface.

## 🔮 Future Enhancements

- Live deployment of the frontend and backend.
- Improved detection of evolving phishing techniques.
- Enhanced explainability for model predictions.
- Expanded testing across diverse email datasets.
- Additional security awareness and reporting features.

## 🔐 Security Notes

- Never commit API keys, passwords, secret keys, or `.env` files.
- Configure required environment variables before deployment.
- Use secure authentication and HTTPS in production.
- Treat model predictions as indicators, not a guarantee that an email is safe or malicious.

## 👨‍💻 Author

**Project:** PhishGuard  
**Domain:** Machine Learning, Cybersecurity, Full-Stack Development

---

⭐ If you find this project useful, consider starring the repository.
