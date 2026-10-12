import { useState, useEffect, useRef } from 'react'
import './App.css'
const API_BASE_URL = "http://127.0.0.1:8000";

function App() {
  const [showLogin, setShowLogin] = useState(true)
  const [userRole, setUserRole] = useState('')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loginError, setLoginError] = useState('')
  const [authToken, setAuthToken] = useState('')
const [currentUser, setCurrentUser] = useState(null)
const [isRegistering, setIsRegistering] = useState(false)
const [registerName, setRegisterName] = useState('')
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [url, setUrl] = useState('')
  const [attachmentName, setAttachmentName] = useState('')
  const [analysisResult, setAnalysisResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [userAction, setUserAction] = useState('')
  const [reviewSubmission, setReviewSubmission] = useState(null)
  
const [myReports, setMyReports] = useState([])
const [myReportsLoading, setMyReportsLoading] = useState(false)
const [myReportsError, setMyReportsError] = useState('')

  const [reviewCases, setReviewCases] = useState([])
const [reviewLoading, setReviewLoading] = useState(false)
const [reviewError, setReviewError] = useState('')
const [reviewNotes, setReviewNotes] = useState({})
const [reviewSavingId, setReviewSavingId] = useState(null)
const [reviewActionError, setReviewActionError] = useState('')
  const [uploadedFile, setUploadedFile] = useState(null)
  const fileInputRef = useRef(null)
  const [riskySenderData, setRiskySenderData] = useState([])
  const [trendData, setTrendData] = useState([])
  const [indicatorData, setIndicatorData] = useState([])
  const [dashboardStats, setDashboardStats] = useState({
  total_analyses: 0,
  phishing: 0,
  suspicious: 0,
  low_risk: 0,
  average_risk_score: 0,
})
  const [analysisHistory, setAnalysisHistory] = useState(() => {
  const savedHistory = localStorage.getItem('phishingAnalysisHistory')

  return savedHistory ? JSON.parse(savedHistory) : []
})
const formatTimestamp = (timestamp) => {
  if (!timestamp) {
    return "Time unavailable"
  }

  try {
    let normalizedTimestamp = timestamp

    // Convert microseconds to JavaScript milliseconds
    normalizedTimestamp = normalizedTimestamp.replace(
      /\.(\d{3})\d+/,
      ".$1"
    )

    const hasTimezone =
      normalizedTimestamp.endsWith("Z") ||
      normalizedTimestamp.includes("+") ||
      normalizedTimestamp.match(/-\d{2}:\d{2}$/)

    let date

    if (hasTimezone) {
      // New records: timezone-aware UTC timestamp
      date = new Date(normalizedTimestamp)
    } else {
      // Old records: already stored as local time
      const [datePart, timePart] =
        normalizedTimestamp.split("T")

      const [year, month, day] =
        datePart.split("-").map(Number)

      const [hour, minute, second] =
        timePart.split(":").map(Number)

      date = new Date(
        year,
        month - 1,
        day,
        hour,
        minute,
        second
      )
    }

    if (Number.isNaN(date.getTime())) {
      return "Time unavailable"
    }

    return date.toLocaleString("en-IN", {
  timeZone: "Asia/Kolkata",
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: true,
}) 
  } catch (error) {
    return "Time unavailable"
  }
}
    
  useEffect(() => {
  localStorage.setItem(
    'phishingAnalysisHistory',
    JSON.stringify(analysisHistory)
  )
}, [analysisHistory])
useEffect(() => {
  fetch(`${API_BASE_URL}/analyses`)
    .then((response) => response.json())
    .then((data) => {
      setAnalysisHistory(
        data.analyses.map((item) => ({
          analysis_id: item.analysis_id,
          sender: item.sender_domain,
          subject: item.subject,
          riskScore: item.risk_score,
          classification: item.classification,
          timestamp: item.created_at,
        }))
      )
    })
    .catch((error) => {
      console.error("Failed to fetch analysis history:", error)
    })
}, [])
   
useEffect(() => {
  fetch(`${API_BASE_URL}/dashboard/stats?refresh=${Date.now()}`)
    .then((response) => response.json())
    .then((data) => {
      setDashboardStats(data)
    })
    .catch((error) => {
      console.error("Failed to fetch dashboard stats:", error)
    })
}, [])
useEffect(() => {
  fetch(`${API_BASE_URL}/dashboard/risky-senders`)
    .then((response) => response.json())
    .then((data) => {
      setRiskySenderData(data.risky_senders)
    })
    .catch((error) => {
      console.error("Failed to fetch risky senders:", error)
    })
}, [])
useEffect(() => {
  fetch(`${API_BASE_URL}/dashboard/trend`)
    .then((response) => response.json())
    .then((data) => {
      setTrendData(data.trend)
    })
    .catch((error) => {
      console.error("Failed to fetch dashboard trend:", error)
    })
}, [])
useEffect(() => {
  fetch(`${API_BASE_URL}/dashboard/indicators`)
    .then((response) => response.json())
    .then((data) => {
      setIndicatorData(data.indicators)
    })
    .catch((error) => {
      console.error("Failed to fetch dashboard indicators:", error)
    })
}, [])
fetch(`${API_BASE_URL}/dashboard/risky-senders`)
  .then((response) => response.json())
  .then((data) => {
    setRiskySenderData(data.risky_senders)
  })
  .catch((error) => {
    console.error("Failed to refresh risky senders:", error)
  })

fetch(`${API_BASE_URL}/dashboard/trend`)
  .then((response) => response.json())
  .then((data) => {
    setTrendData(data.trend)
  })
  .catch((error) => {
    console.error("Failed to refresh dashboard trend:", error)
  })

fetch(`${API_BASE_URL}/dashboard/indicators`)
  .then((response) => response.json())
  .then((data) => {
    setIndicatorData(data.indicators)
  })
  .catch((error) => {
    console.error("Failed to refresh dashboard indicators:", error)
  })
const handleFileUpload = async (event) => {
  const file = event.target.files[0]

  if (!file) {
    return
  }

  setUploadedFile(file)

  try {
    const content = await file.text()

    if (file.name.toLowerCase().endsWith('.txt')) {
  const fromMatch = content.match(/^From:\s*(.+)$/im)
  const subjectMatch = content.match(/^Subject:\s*(.+)$/im)
  const urlMatch = content.match(/https?:\/\/[^\s<>"']+/i)

  setSender(fromMatch ? fromMatch[1].trim() : '')
  setSubject(subjectMatch ? subjectMatch[1].trim() : '')
  setBody(content)
  setUrl(urlMatch ? urlMatch[0] : '')

  return
}
    if (file.name.toLowerCase().endsWith('.eml')) {
      const parts = content.split(/\r?\n\r?\n/)
      const headers = parts[0] || ''
      const emailBody = parts.slice(1).join('\n\n')

      const fromMatch = headers.match(/^From:\s*(.+)$/im)
      const subjectMatch = headers.match(/^Subject:\s*(.+)$/im)

      setSender(fromMatch ? fromMatch[1].trim() : '')
      setSubject(subjectMatch ? subjectMatch[1].trim() : '')
      setBody(emailBody)
      const urlMatch = content.match(/https?:\/\/[^\s<>"']+/i)

      setUrl(urlMatch ? urlMatch[0] : '')
    }
  } catch (error) {
    console.error('File Reading Error:', error)

    alert('Unable to read the selected email file.')
  }
}


const handleLogin = async (event) => {
  event.preventDefault()
  setLoginError('')

  const email = loginEmail.trim().toLowerCase()

  if (!email || !loginPassword) {
    setLoginError('Please enter your email and password.')
    return
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password: loginPassword,
      }),
    })

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        typeof data.detail === 'string'
          ? data.detail
          : 'Login failed. Please check your credentials.'
      )
    }

    setAuthToken(data.access_token)
    setCurrentUser(data.user)
    setUserRole(data.user.role)
    setLoginEmail(data.user.email)
    setLoginPassword('')
    setShowLogin(false)
  } catch (error) {
    console.error('Login error:', error)
    setLoginError(error.message || 'Unable to connect to the backend.')
  }
}

const handleRegister = async (event) => {
  event.preventDefault()
  setLoginError('')

  const name = registerName.trim()
  const email = loginEmail.trim().toLowerCase()

  if (!name || !email || !loginPassword) {
    setLoginError('Please enter your name, email, and password.')
    return
  }

  if (loginPassword.length < 8) {
    setLoginError('Password must contain at least 8 characters.')
    return
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
        email,
        password: loginPassword,
      }),
    })

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        typeof data.detail === 'string'
          ? data.detail
          : 'Registration failed.'
      )
    }

    setIsRegistering(false)
    setRegisterName('')
    setLoginPassword('')
    setLoginError('Registration successful! Please sign in.')
  } catch (error) {
    console.error('Registration error:', error)
    setLoginError(error.message || 'Unable to connect to the backend.')
  }
}


useEffect(() => {
  if (userRole === 'ADMIN' && !showLogin) {
    fetchReviewCases()
  }
}, [userRole, showLogin])

useEffect(() => {
  if (userRole === 'USER' && !showLogin) {
    fetchMyReports()
  }
}, [userRole, showLogin, loginEmail])



const handleAnalyze = async () => {
  if (!sender.trim() && !subject.trim() && !body.trim()) {
    alert(
      'Please enter at least the sender, subject, or email body before analyzing.'
    )
    return
  }

  setIsAnalyzing(true)

  try {
    
const response = await fetch("http://127.0.0.1:8000/analyze", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${authToken}`,
  },
  body: JSON.stringify({
    sender,
    subject,
    body,
  }),
});


    
const data = await response.json()


if (!response.ok) {
  alert(
    typeof data?.detail === 'string'
      ? data.detail
      : 'Unable to analyze the email. Please check your inputs.'
  )
  setIsAnalyzing(false)
  return
}

console.log('Analysis Result:', data)

setAnalysisResult(data)

   setAnalysisHistory((previousHistory) => [
  ...previousHistory,
  {
    analysis_id: data?.analysis_id,
    sender: sender,
    subject: subject,
    riskScore: data?.risk_analysis?.risk_score,
    classification: data?.risk_analysis?.classification,
    timestamp: new Date().toISOString(),
  },
])

setSender("")
setSubject("")
setBody("")
setUrl("")
setAttachmentName("")

  fetch(`${API_BASE_URL}/dashboard/stats`)
  .then((response) => response.json())
  .then((data) => {
    setDashboardStats(data)
  })
  .catch((error) => {
    console.error("Failed to refresh dashboard stats:", error)
  })
    setIsAnalyzing(false)
  } catch (error) {
    console.error('Analysis Error:', error)

    alert(
      'Unable to connect to the analysis server. Please make sure the backend is running.'
    )

    setIsAnalyzing(false)
  }
}

const handleReportToAdmin = async () => {
  const analysisId = analysisResult?.analysis_id

  if (!analysisId) {
    alert('Please analyze the email before reporting it.')
    return
  }

  if (userRole !== 'USER') {
    alert('Please log in as a user to report an analysis.')
    return
  }

  try {
    const response = await fetch(`${API_BASE_URL}/review-cases`, {
      method: 'POST',
      headers: {
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${authToken}`,
},
      body: JSON.stringify({
        analysis_id: analysisId,
        reported_by: loginEmail.trim().toLowerCase(),
      }),
    })

    const data = await response.json()

    if (!response.ok) {
      if (response.status === 409) {
        alert('This analysis already has a pending report.')
        return
      }

      throw new Error(
        data?.detail?.message ||
        data?.detail ||
        'Unable to submit the report.'
      )
    }

    
setUserAction('reported')

setReviewSubmission({
  review_id: data.review_id,
  analysis_id: data.analysis_id,
  status: data.status,
})


  } catch (error) {
    console.error('Report submission error:', error)
    alert(
      typeof error.message === 'string'
        ? error.message
        : 'Unable to connect to the backend.'
    )
  }
}

const fetchReviewCases = async () => {
  setReviewLoading(true)
  setReviewError('')

  try {
    const response = await fetch(
  `${API_BASE_URL}/review-cases`,
  {
    headers: {
      Authorization: `Bearer ${authToken}`,
    },
  }
)
    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        data?.detail || 'Unable to load review cases.'
      )
    }

    setReviewCases(data.review_cases || [])
  } catch (error) {
    console.error('Review cases fetch error:', error)
    setReviewError(error.message || 'Unable to load review cases.')
  } finally {
    setReviewLoading(false)
  }
}

const handleReviewDecision = async (reviewId, status) => {
  const confirmed = window.confirm(
    `Save this review as ${status.replaceAll('_', ' ')}?`
  )

  if (!confirmed) return

  setReviewSavingId(reviewId)
  setReviewActionError('')

  try {
    const response = await fetch(
      `${API_BASE_URL}/review-cases/${reviewId}`,
      {
        method: 'PATCH',
        headers: {
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${authToken}`,
},
        body: JSON.stringify({
          status,
          admin_notes: reviewNotes[reviewId] || '',
          reviewed_by: loginEmail.trim().toLowerCase(),
        }),
      }
    )

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        typeof data?.detail === 'string'
          ? data.detail
          : data?.detail?.message || 'Unable to save review decision.'
      )
    }

    await fetchReviewCases()
    alert('Review decision saved successfully.')
  } catch (error) {
    console.error('Review decision error:', error)
    setReviewActionError(
      error.message || 'Unable to save review decision.'
    )
  } finally {
    setReviewSavingId(null)
  }
}


const fetchMyReports = async () => {
  const email = loginEmail.trim().toLowerCase()

  if (!email || userRole !== 'USER') {
    setMyReportsError('Please sign in to view your reports.')
    return
  }

  setMyReportsLoading(true)
  setMyReportsError('')

  try {
    const response = await fetch(
  `${API_BASE_URL}/review-cases/user/${encodeURIComponent(email)}`,
  {
    headers: {
      Authorization: `Bearer ${authToken}`,
    },
  }
)

    const data = await response.json().catch(() => ({}))

    if (!response.ok) {
      throw new Error(
        typeof data?.detail === 'string'
          ? data.detail
          : 'Unable to load your reports. Please try again.'
      )
    }

    setMyReports(data.review_cases || [])
  } catch (error) {
    console.error('My reports fetch error:', error)
    setMyReportsError(
      error.message || 'Unable to connect to the server.'
    )
  } finally {
    setMyReportsLoading(false)
  }
}




const handleClear = () => {
  setSender('')
  setSubject('')
  setBody('')
  setUrl('')
  setAttachmentName('')
  setAnalysisResult(null)
  setUserAction('')
  setUploadedFile(null)
  if (fileInputRef.current) {
  fileInputRef.current.value = ''
}
}
const handleDeleteAnalysis = async (analysisId) => {
  try {
    const response = await fetch(
      `${API_BASE_URL}/analyses/${analysisId}`,
      {
        method: 'DELETE',
      }
    )

   if (!response.ok) {
  const errorData = await response.json()
  throw new Error(
    errorData.detail || 'Failed to delete analysis'
  )
}

    setAnalysisHistory((previousHistory) =>
      previousHistory.filter(
        (item) => item.analysis_id !== analysisId
      )
    )

    const statsResponse = await fetch(
      `${API_BASE_URL}/dashboard/stats`
    )

    const statsData = await statsResponse.json()
    setDashboardStats(statsData)

    const riskyResponse = await fetch(
      `${API_BASE_URL}/dashboard/risky-senders`
    )

    const riskyData = await riskyResponse.json()
    setRiskySenderData(riskyData.risky_senders)

    const trendResponse = await fetch(
      `${API_BASE_URL}/dashboard/trend`
    )

    const trendDataResponse = await trendResponse.json()
    setTrendData(trendDataResponse.trend)

    const indicatorResponse = await fetch(
      `${API_BASE_URL}/dashboard/indicators`
    )

    const indicatorDataResponse = await indicatorResponse.json()
    setIndicatorData(indicatorDataResponse.indicators)

  
} catch (error) {
  console.error('Delete Analysis Error:', error)
  alert(`Delete failed: ${error.message}`)
}

}
const handleClearHistory = async () => {
  try {
    const response = await fetch(
      `${API_BASE_URL}/analyses`,
      {
        method: 'DELETE',
      }
    )

    if (!response.ok) {
      throw new Error('Failed to clear history')
    }

    setAnalysisHistory([])
    setDashboardStats({
  total_analyses: 0,
  phishing: 0,
  suspicious: 0,
  low_risk: 0,
  average_risk_score: 0,
})
setRiskySenderData([])
setTrendData([])
setIndicatorData([])
    localStorage.removeItem('phishingAnalysisHistory')
  } catch (error) {
    console.error('Clear History Error:', error)

    alert('Unable to clear analysis history.')
  }
}
const totalAnalyses = dashboardStats.total_analyses

const lowRiskCount = dashboardStats.low_risk

const suspiciousCount = dashboardStats.suspicious

const highRiskCount = dashboardStats.phishing
const moderateRiskCount = analysisHistory.filter(
  (item) => item.classification === 'MODERATE RISK'
).length

const phishingCount =
  dashboardStats.phishing + dashboardStats.suspicious

const legitimateCount = analysisHistory.filter(
  (item) => item.classification === 'LOW RISK'
).length
const riskySenders = analysisHistory
  .filter(
    (item) =>
      item.classification?.includes('PHISHING') ||
      item.classification === 'SUSPICIOUS'
  )
  .reduce((senders, item) => {
    const sender = item.sender || 'Unknown Sender'

    if (!senders[sender]) {
      senders[sender] = {
        count: 0,
        highestRisk: 0,
      }
    }

    senders[sender].count += 1
    senders[sender].highestRisk = Math.max(
      senders[sender].highestRisk,
      Number(item.riskScore || 0)
    )

    return senders
  }, {})

const topRiskySenders = Object.entries(riskySenders)
  .sort((a, b) => b[1].highestRisk - a[1].highestRisk)
  .slice(0, 5)
  const lastSevenDays = Array.from({ length: 7 }, (_, index) => {
  const date = new Date()
  date.setDate(date.getDate() - (6 - index))

  const dateKey = date.toISOString().split('T')[0]

  const backendDay = trendData.find(
    (item) => item.date === dateKey
  )

  return {
    date,
    label: date.toLocaleDateString('en-US', {
      weekday: 'short',
    }),
    dateKey,
    riskyCount: backendDay
      ? backendDay.risky_count
      : 0,
  }
})
const averageRisk = dashboardStats.average_risk_score
const topIndicators = indicatorData
  .sort((a, b) => b.count - a.count)
  .slice(0, 5)
    const microLessons = [
  {
    title: 'Hover to Verify Links',
    text: 'Before clicking an email link, check where it actually leads. Look carefully at the domain name and watch for unusual spellings, suspicious subdomains, or unexpected destinations.',
    tip: 'Never trust a link only because the email looks professional.',
  },
  {
    title: 'Understand URL Anatomy',
    text: 'Look at the domain before clicking. Attackers may use unusual subdomains, misleading paths, or deceptive domain structures to make a link appear trustworthy.',
    tip: 'Check the actual domain instead of relying on the visible link text.',
  },
  {
    title: 'Check the Sender',
    text: 'A familiar-looking display name does not always mean the message came from a trusted organization. Inspect the complete sender address and domain.',
    tip: 'Always verify the sender domain before responding to sensitive requests.',
  },
  {
    title: 'Beware of Invoice Scams',
    text: 'Unexpected payment requests, invoice warnings, or urgent billing messages can be used to create financial pressure.',
    tip: 'Verify payment requests through an independent trusted channel.',
  },
  {
    title: 'Think Before Trusting QR Codes',
    text: 'QR codes in unexpected emails can hide destinations that are difficult to inspect before opening.',
    tip: 'Treat unexpected QR codes like suspicious links and verify the source first.',
  },
]

const todayLesson =
  microLessons[new Date().getDay() % microLessons.length]
  if (showLogin) {
  return (
    <div className="login-page">

      <div className="login-background">
        <div className="login-glow login-glow-one"></div>
        <div className="login-glow login-glow-two"></div>
      </div>

      <div className="login-container">

        {/* Branding */}
        <div className="login-brand">
          <div className="login-brand-icon">
            🛡️
          </div>

          <h1>PhishGuard</h1>

          <p>
            Phishing Detection & Awareness
          </p>
        </div>

        {/* Login Card */}
        <div className="login-card">

          <div className="login-header">
            <h2>{isRegistering ? 'Create Your Account' : 'Welcome Back'}</h2>

            <p>
  {isRegistering
    ? 'Register to access your phishing security dashboard.'
    : 'Sign in to access your security dashboard.'}
</p>
          </div>
{isRegistering && (
  <div className="login-form-group">
    <label htmlFor="register-name">Full Name</label>
    <div className="login-input-wrapper">
      <input
        id="register-name"
        type="text"
        placeholder="Enter your full name"
        value={registerName}
        onChange={(event) => setRegisterName(event.target.value)}
        required
        minLength={2}
        maxLength={100}
      />
    </div>
  </div>
)}
          <form onSubmit={isRegistering ? handleRegister : handleLogin}>

            {/* Email */}
            <div className="login-form-group">

              <label htmlFor="login-email">
                Email Address
              </label>

              <div className="login-input-wrapper">

                <span className="login-input-icon">
                  ✉️
                </span>

                <input
                  id="login-email"
                  type="email"
                  placeholder="Enter your email"
                  value={loginEmail}
                  onChange={(event) =>
                    setLoginEmail(event.target.value)
                  }
                />

              </div>

            </div>

            {/* Password */}
            <div className="login-form-group">

              <label htmlFor="login-password">
                Password
              </label>

              <div className="login-input-wrapper">

                <span className="login-input-icon">
                  🔒
                </span>

                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your password"
                  value={loginPassword}
                  onChange={(event) =>
                    setLoginPassword(event.target.value)
                  }
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() =>
                    setShowPassword(!showPassword)
                  }
                  aria-label={
                    showPassword
                      ? 'Hide password'
                      : 'Show password'
                  }
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>

              </div>

            </div>

            {/* Remember + Forgot */}
            <div className="login-options">

              <label className="remember-me">
                <input type="checkbox" />
                <span>Remember me</span>
              </label>

              <button
                type="button"
                className="forgot-password"
                onClick={() =>
                  alert(
                    'Password recovery will be available after backend authentication is implemented.'
                  )
                }
              >
                Forgot password?
              </button>

            </div>

            {/* Error */}
            {loginError && (
              <div className="login-error">
                {loginError && (
  <div
    className={
      loginError.toLowerCase().includes('successful')
        ? 'login-success'
        : 'login-error'
    }
    role="status"
  >
    {loginError.toLowerCase().includes('successful') ? '✅' : '⚠️'}{' '}
    {loginError}
  </div>
)}
              </div>
            )}

            {/* Login Button */}
            <button
              type="submit"
              className="login-button"
            >
              <span>🔐</span>
              {isRegistering ? 'Create Account' : 'Sign In'}
            </button>

          </form>
<div className="auth-toggle">
  <span>
    {isRegistering
      ? 'Already have an account?'
      : "Don't have an account?"}
  </span>

  <button
    type="button"
    className="forgot-password"
    onClick={() => {
      setIsRegistering((previous) => !previous)
      setLoginError('')
      setLoginPassword('')
    }}
  >
    {isRegistering ? 'Sign In' : 'Create Account'}
  </button>
</div>
          {/* Security Notice */}
          <div className="login-security-note">
            <span>🛡️</span>

            <p>
              Secure access to your phishing analysis
              dashboard.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div className="login-footer">
          <span>PhishGuard Security Platform</span>
          <span>•</span>
          <span>Defensive Cybersecurity</span>
        </div>

      </div>

    </div>
  )
}
  return(
    <div className="app">

      
{/* Header */}
<header className="header">

  <div className="brand">
    <div className="brand-icon">🛡️</div>

    <div>
      <h1>PhishGuard</h1>
      <p>Phishing Detection & Awareness</p>
    </div>
  </div>

  <div className="header-right">

    <div className="status">
      <span className="status-dot"></span>
      System Online
    </div>

    <div className="profile-section">

      <div className="profile-avatar">
        {userRole === 'ADMIN' ? '🛡️' : '👤'}
      </div>

      <div className="profile-info">
        <strong>
          {userRole === 'ADMIN' ? 'Administrator' : 'User'}
        </strong>

        <span>
          {userRole || 'GUEST'}
        </span>
      </div>

    </div>

    <button
      className="logout-button"
      onClick={() => {
        setShowLogin(true)
        setLoginEmail('')
        setLoginPassword('')
        setLoginError('')
        setAnalysisResult(null)
      }}
    >
      ↪ Logout
    </button>

  </div>

</header>


{/* Role-Based Navigation */}

<nav className="role-navigation">
  {(
    userRole === 'ADMIN'
      ? [
          {
            label: '🛡️ Admin Overview',
            target: 'admin-overview',
          },
          {
            label: '🔍 Email Analysis',
            target: 'analysis-section',
          },
          {
            label: '📊 Security Awareness',
            target: 'awareness-section',
          },
        ]
      : [
          {
            label: '🏠 My Dashboard',
            target: 'dashboard-top',
          },
          {
            label: '🔍 Analyze Email',
            target: 'analysis-section',
          },
          {
            label: '📚 Learn Security',
            target: 'awareness-section',
          },
        ]
  ).map((item) => (
    <button
      key={item.target}
      className="role-nav-item"
      onClick={() => {
        const target =
          item.target === 'dashboard-top'
            ? document.querySelector('.dashboard')
            : document.getElementById(item.target) ||
              document.querySelector(`.${item.target}`)

        target?.scrollIntoView({
          behavior: 'smooth',
          block: 'start',
        })
      }}
    >
      {item.label}
    </button>
  ))}
</nav>


      {/* Main Dashboard */}
      <main className="dashboard">
        

        
{/* Page Introduction */}
<section className="page-intro">
  <div>
    <p className="eyebrow">
      {userRole === 'ADMIN' ? 'ADMINISTRATION' : 'SECURITY ANALYSIS'}
    </p>

    <h2>
      {userRole === 'ADMIN' ? (
        <>
          PhishGuard
          <span> Admin Dashboard</span>
        </>
      ) : (
        <>
          Phishing Email
          <span> Detection Dashboard</span>
        </>
      )}
    </h2>

    <p className="intro-text">
      {userRole === 'ADMIN'
        ? 'Monitor phishing threats, review analysis activity, and manage security insights.'
        : 'Analyze suspicious emails using rule-based detection and machine learning.'}
    </p>
  </div>
</section>


{/* Admin Overview */}
{userRole === 'ADMIN' && (
  <section className="admin-overview" id="admin-overview">
    <div className="section-header">
      <div>
        <h3>Security Overview</h3>
        <p>Summary of recorded email analysis activity.</p>
      </div>
      <span className="overview-live">● Live data</span>
    </div>

    <div className="admin-stats-grid">
      <div className="admin-stat-card">
        <span className="admin-stat-icon">📨</span>
        <p>Total Analyses</p>
        <h3>{dashboardStats.total_analyses}</h3>
      </div>

      <div className="admin-stat-card">
        <span className="admin-stat-icon">🚨</span>
        <p>Phishing Detected</p>
        <h3>{dashboardStats.phishing}</h3>
      </div>

      <div className="admin-stat-card">
        <span className="admin-stat-icon">⚠️</span>
        <p>Suspicious</p>
        <h3>{dashboardStats.suspicious}</h3>
      </div>

      <div className="admin-stat-card">
        <span className="admin-stat-icon">📊</span>
        <p>Average Risk Score</p>
        <h3>{dashboardStats.average_risk_score}</h3>
      </div>
    </div>
  </section>
)}

{userRole === 'ADMIN' && (
  <section className="admin-overview review-queue-section">
    <div className="section-header">
      <div>
        <h3>📋 Admin Review Queue</h3>
        <p>Review emails reported by users.</p>
      </div>

      <button
        className="refresh-button"
        onClick={fetchReviewCases}
        disabled={reviewLoading}
      >
        {reviewLoading ? 'Loading...' : '↻ Refresh'}
      </button>
    </div>

    {reviewError && (
      <p className="action-message reported-message">
        {reviewError}
      </p>
    )}
    
{reviewActionError && (
  <p className="action-message reported-message">
    {reviewActionError}
  </p>
)}


    {reviewLoading && (
      <p>Loading reported emails...</p>
    )}

    {!reviewLoading && !reviewError && reviewCases.length === 0 && (
      <p>No reports found.</p>
    )}

    <div className="review-cases-list">
      {reviewCases.map((item) => (
        <div className="admin-stat-card" key={item.review_id}>
          <div className="section-header">
            <div>
              <h4>{item.subject || '(No subject)'}</h4>
              <p>Review ID: #{item.review_id}</p>
            </div>

            <span className="overview-live">
              {item.status}
            </span>
          </div>

          <p>
            <strong>Analysis ID:</strong> {item.analysis_id}
          </p>
          <p>
            <strong>Reported by:</strong> {item.reported_by}
          </p>
          <p>
            <strong>Sender domain:</strong> {item.sender_domain || 'Unknown'}
          </p>
          <p>
            <strong>Risk score:</strong> {item.risk_score}/100
          </p>
          <p>
            <strong>Classification:</strong> {item.classification}
          </p>

          
{item.admin_notes && (
  <p>
    <strong>Saved Admin notes:</strong> {item.admin_notes}
  </p>
)}

{item.status === 'PENDING' && (
  <div className="review-decision-controls">
    <label htmlFor={`review-notes-${item.review_id}`}>
      Admin Notes
    </label>

    <textarea
      id={`review-notes-${item.review_id}`}
      value={reviewNotes[item.review_id] || ''}
      onChange={(event) =>
        setReviewNotes((previous) => ({
          ...previous,
          [item.review_id]: event.target.value,
        }))
      }
      placeholder="Enter the reason for your decision..."
      rows={3}
    />

    <div className="review-decision-buttons">
      
<button
  type="button"
  className="decision-phishing"
  disabled={reviewSavingId === item.review_id}
  onClick={() =>
    handleReviewDecision(
      item.review_id,
      'CONFIRMED_PHISHING'
    )
  }
>
  🚨 Confirm Phishing
</button>


      
<button
  type="button"
  className="decision-safe"
  disabled={reviewSavingId === item.review_id}
  onClick={() =>
    handleReviewDecision(
      item.review_id,
      'FALSE_POSITIVE'
    )
  }
>
  ✅ False Positive
</button>

      
<button
  type="button"
  className="decision-investigate"
  disabled={reviewSavingId === item.review_id}
  onClick={() =>
    handleReviewDecision(
      item.review_id,
      'NEEDS_INVESTIGATION'
    )
  }
>
  🔎 Needs Investigation
</button>

    </div>

    {reviewSavingId === item.review_id && (
      <p>Saving decision...</p>
    )}
  </div>
)}

        </div>
      ))}
    </div>
  </section>
)}

{/* My Reports Section - User Only */}
{userRole === 'USER' && (
  <section className="admin-overview review-queue-section">
    <div className="section-header">
      <div>
        <h3>📨 My Reports</h3>
        <p>Track the status of emails you reported to Admin.</p>
      </div>

      <button
        type="button"
        className="refresh-button"
        onClick={fetchMyReports}
        disabled={myReportsLoading}
      >
        {myReportsLoading ? 'Loading...' : '↻ Refresh'}
      </button>
    </div>

    {myReportsError && (
      <p className="action-message reported-message">
        {myReportsError}
      </p>
    )}

    {myReportsLoading && (
      <p>Loading your reports...</p>
    )}

    {!myReportsLoading &&
      !myReportsError &&
      myReports.length === 0 && (
        <p>You have not reported any emails yet.</p>
      )}

    <div className="review-cases-list">
      {myReports.map((item) => (
        <div className="admin-stat-card" key={item.review_id}>
          <div className="section-header">
            <div>
              <h4>{item.subject || '(No subject)'}</h4>
              <p>Review ID: #{item.review_id}</p>
            </div>

            <span className="overview-live">
              {item.status.replaceAll('_', ' ')}
            </span>
          </div>

          <p>
            <strong>Analysis ID:</strong> {item.analysis_id}
          </p>

          <p>
            <strong>Sender:</strong> {item.sender_domain || 'Unknown'}
          </p>

          <p>
            <strong>Risk Score:</strong> {item.risk_score}/100
          </p>

          <p>
            <strong>Classification:</strong> {item.classification}
          </p>

          {item.admin_notes && (
            <p>
              <strong>Admin Notes:</strong> {item.admin_notes}
            </p>
          )}

         {formatTimestamp(item.reviewed_at) && (
            <p>
              <strong>Reviewed At:</strong> {formatTimestamp(item.reviewed_at)}
            </p>
          )}
        </div>
      ))}
    </div>
  </section>
)}


        {/* Email Analysis Section */}
        <section className="analysis-section">

          <div className="section-header">
            <div>
              <h3>Analyze Email</h3>
              <p>
                Enter the email details below to detect phishing indicators.
              </p>
            </div>
          </div>


          {/* Email Form */}
          <div className="email-form">

            <div className="form-group">
              <label>Sender Email</label>

              <input
                type="email"
                placeholder="example@company.com"
                value={sender}
                onChange={(event) => setSender(event.target.value)}
              />
            </div>


            <div className="form-group">
              <label>Subject</label>

              <input
  type="text"
  placeholder="Enter email subject"
  value={subject}
  onChange={(event) => setSubject(event.target.value)}
/>
            </div>


            <div className="form-group">
              <label>Email Body</label>

              <textarea
  rows="8"
  placeholder="Paste the email content here..."
  value={body}
  onChange={(event) => setBody(event.target.value)}
></textarea>
            </div>


            <div className="form-group">
              <label>URL</label>

              <input
  type="text"
  placeholder="https://example.com"
  value={url}
  onChange={(event) => setUrl(event.target.value)}
/>
            </div>


            <div className="form-group">
              <label>Attachment Name <span>(Optional)</span></label>

              <input
  type="text"
  placeholder="example.pdf"
  value={attachmentName}
  onChange={(event) => setAttachmentName(event.target.value)}
  
/>
            </div>
            <div className="form-group">
  <label>Upload Sample Email</label>

  <input
    ref={fileInputRef}
    type="file"
    accept=".txt,.eml"
    onChange={handleFileUpload}
  />

  {uploadedFile && (
    <p className="file-info">
      📎 {uploadedFile.name}
    </p>
  )}
</div>


            <button
  className="analyze-button"
  onClick={handleAnalyze}
  disabled={isAnalyzing}
>
  {isAnalyzing ? '⏳ Analyzing...' : '🔍 Analyze Email'}
</button>
<button
  className="clear-button"
  onClick={handleClear}
>
  🧹 Clear
</button>

          </div>

        </section>


        {/* Results Section */}
        <section className="results-section">

          <div className="section-header">
            <div>
              <h3>Analysis Results</h3>
              <p>
                Detection results and security indicators will appear here.
              </p>
            </div>
          </div>


          <div className="result-grid">

            <div className="result-card risk-card">
              <p>Risk Score</p>

               <h4>
                {analysisResult?.risk_analysis?.risk_score ?? '--'}
               </h4>
               <p className="risk-label">
  {analysisResult?.risk_analysis?.classification ?? 'Awaiting analysis'}
</p>
            </div>
            {analysisResult?.risk_analysis?.reasons?.length > 0 && (
  <div className="reasons-section">
    <h3>Why was this email flagged?</h3>

    <div className="reason-list">
      {analysisResult.risk_analysis.reasons.map((reason, index) => (
        <div className="reason-card" key={index}>
          <strong>{reason.indicator}</strong>

          <span>+{reason.points} points</span>

          <p>{reason.explanation}</p>
        </div>
      ))}
    </div>
  </div>
)}
{analysisResult?.recommendations?.length > 0 && (
  <div className="recommendations-section">
    <h3>Security Recommendations</h3>

    <ul className="recommendation-list">
      {analysisResult.recommendations.map((recommendation, index) => (
        <li key={index}>
          🛡️ {recommendation}
        </li>
      ))}
    </ul>
  </div>
)}
            <div className="result-card">
  <p>Classification</p>
  <h4>
    {analysisResult?.risk_analysis?.classification ?? 'Waiting for analysis'}
  </h4>
  <p className="classification-info">
  Rule-based security assessment
</p>
</div>
            

          </div>

        </section>
        {analysisResult && (
  <div className="action-section">
    <h3>Security Actions</h3>
    <p>Take action based on the analysis result.</p>
<div className="result-card ml-card">
  <p>🤖 ML Prediction</p>

  <h4>
    {analysisResult?.ml_analysis?.classification ?? '--'}
  </h4>

  <p className="classification-info">
    Random Forest ML model
  </p>
  <div className="ml-interpretation">
  <strong>Interpretation</strong>
  <p>
    The ML model suspects phishing (
    {analysisResult.ml_analysis.phishing_probability}% probability),
    while the rule-based assessment rates this email as{' '}
    {analysisResult.risk_analysis.classification} (
    {analysisResult.risk_analysis.risk_score}/100).
    Verify the sender and links before taking action.
  </p>
</div>

  {analysisResult?.ml_analysis && (
    <div className="ml-probabilities">

      <div className="ml-stat">
        <span>Confidence</span>
        <strong>
          {analysisResult.ml_analysis.confidence}%
        </strong>
      </div>

      <div className="ml-stat">
        <span>Legitimate Probability</span>
        <strong>
          {analysisResult.ml_analysis.legitimate_probability}%
        </strong>
      </div>

      <div className="ml-stat">
        <span>Phishing Probability</span>
        <strong>
          {analysisResult.ml_analysis.phishing_probability}%
        </strong>
      </div>

    </div>
  )}
</div>
    <div className="action-buttons">
      
<button
  className="report-button"
  onClick={handleReportToAdmin}
>
  📨 Report to Admin for Review
</button>


      <button
        className="safe-button"
        onClick={() => setUserAction('safe')}
      >
        ✅ Mark Safe
      </button>
    </div>

    {userAction === 'reported' && (
      <div className="action-message reported-message">
        📨 Email submitted to Admin for review.
      </div>
    )}
    
{reviewSubmission && (
  <div className="action-message reported-message">
    <h4>✅ Report Submitted Successfully</h4>

    <p>
      <strong>Review ID:</strong>{' '}
      #{reviewSubmission.review_id}
    </p>

    <p>
      <strong>Analysis ID:</strong>{' '}
      {reviewSubmission.analysis_id}
    </p>

    <p>
      <strong>Review Status:</strong>{' '}
      {reviewSubmission.status}
    </p>

    <p>
      Your report has been submitted to Admin for review.
    </p>
  </div>
)}


    {userAction === 'safe' && (
      <div className="action-message safe-message">
        ✅ Email marked as safe.
      </div>
    )}
  </div>
)}
{/* Analysis History */}
<section className="history-section">

  <div className="section-header">
    <div>
      <h3>Analysis History</h3>
      <p>Previously analyzed email results.</p>
      
    </div>
  </div>
  <button
  className="clear-history-button"
  onClick={handleClearHistory}
>
  🗑️ Clear History
</button>

  {analysisHistory.length === 0 ? (
    <div className="empty-history">
      <p>No email analysis history yet.</p>
    </div>
  ) : (
    <div className="history-list">

      {analysisHistory.map((item, index) => (
        <div
  className="history-card"
  key={item.analysis_id || index}
>

          <div className="history-main">
            <h4>{item.subject || 'No Subject'}</h4>
            <p>{item.sender || 'Unknown Sender'}</p>
           <p className="history-time">
             🕒 {formatTimestamp(item.timestamp)}
           </p>
          </div>

          <div className="history-risk">
            <strong>{item.riskScore ?? '--'}</strong>
            <span>{item.classification || 'Unknown'}</span>
          </div>
          <button
  className="delete-analysis-btn"
  onClick={() => handleDeleteAnalysis(item.analysis_id)}
>
  Delete
</button>

        </div>
      ))}

    </div>
  )}
  

</section>
{/* Analytics Section */}
<section className="analytics-section">

  <div className="section-header">
    <div>
      <h3>Security Analytics</h3>
      <p>Overview of your email analysis activity.</p>
    </div>
  </div>

  <div className="analytics-grid">

    <div className="analytics-card">
      <span className="analytics-icon">📊</span>
      <p>Total Analyses</p>
      <h4>{totalAnalyses}</h4>
    </div>

    <div className="analytics-card">
      <span className="analytics-icon">🚨</span>
      <p>Phishing / Suspicious</p>
      <h4>{phishingCount}</h4>
    </div>

    <div className="analytics-card">
      <span className="analytics-icon">✅</span>
      <p>Low Risk</p>
      <h4>{lowRiskCount}</h4>
    </div>

    <div className="analytics-card">
      <span className="analytics-icon">🎯</span>
      <p>Average Risk</p>
      <h4>{averageRisk}</h4>
    </div>
        <div className="analytics-card">
      <span className="analytics-icon">🔎</span>
      <p>Top Security Indicators</p>

      {topIndicators.length === 0 ? (
        <h4>--</h4>
      ) : (
        <div>
          {topIndicators.map((indicator) => (
            <p key={indicator.indicator_type}>
              {indicator.indicator_type}: {indicator.count}
            </p>
          ))}
        </div>
      )}
    </div>

  </div>

</section>
{/* Risk Distribution */}
<section className="risk-distribution-section">
  <div className="section-header">
    <div>
      <h3>Risk Distribution</h3>
      <p>Breakdown of analyzed emails by security classification.</p>
    </div>
  </div>

  <div className="risk-distribution-grid">

    <div className="distribution-card low-risk">
      <span>🟢</span>
      <p>Low Risk</p>
      <h4>{lowRiskCount}</h4>
    </div>

    <div className="distribution-card moderate-risk">
      <span>🟡</span>
      <p>Moderate Risk</p>
      <h4>{moderateRiskCount}</h4>
    </div>

    <div className="distribution-card suspicious">
      <span>🟠</span>
      <p>Suspicious</p>
      <h4>{suspiciousCount}</h4>
    </div>

    <div className="distribution-card high-risk">
      <span>🔴</span>
      <p>High Risk</p>
      <h4>{highRiskCount}</h4>
    </div>

  </div>
</section>
{/* Top Risky Senders */}
<section className="top-risk-section">
  <div className="section-header">
    <div>
      <h3>Top Risky Senders</h3>
      <p>Senders associated with suspicious or phishing emails.</p>
    </div>
  </div>

  {riskySenderData.length === 0 ? (
    <div className="empty-risky-senders">
      <p>No risky senders detected yet.</p>
    </div>
  ) : (
    <div className="risky-sender-list">
      {riskySenderData.map((sender) => (
        <div
          className="risky-sender-card"
          key={sender.sender_domain}
        >
          <div className="sender-info">
            <span className="sender-icon">⚠️</span>

            <div>
              <h4>{sender.sender_domain}</h4>
              <p>
                {sender.count} risky email(s) detected
              </p>
            </div>
          </div>

          <div className="sender-risk">
            <strong>{sender.average_risk_score}</strong>
            <span>Risk Score</span>
          </div>
        </div>
      ))}
    </div>
  )}
</section>
  {/* 7-Day Security Trend */}
<section className="trend-section">
  <div className="section-header">
    <div>
      <h3>7-Day Security Trend</h3>
      <p>Risky email activity recorded over the last seven days.</p>
    </div>
  </div>

  <div className="trend-chart">
    {lastSevenDays.map((day) => (
      <div className="trend-item" key={day.dateKey}>
        <div className="trend-bar-container">
          <div
            className="trend-bar"
            style={{
              height: `${Math.max(day.riskyCount * 35, 8)}px`,
            }}
          >
            {day.riskyCount > 0 && (
              <span>{day.riskyCount}</span>
            )}
          </div>
        </div>

        <strong>{day.label}</strong>
      </div>
    ))}
  </div>
</section>


       {/* Awareness Section */}
<section className="awareness-section">
<div className="micro-lesson">
  <div className="micro-lesson-icon">💡</div>

  <div className="micro-lesson-content">
    <span className="lesson-label">MICRO-LESSON OF THE DAY</span>

    <h3>{todayLesson.title}</h3>

<p>{todayLesson.text}</p>

<div className="lesson-tip">
  🛡️ <strong>Security Tip:</strong> {todayLesson.tip}
</div>
  </div>
</div>
  <div className="section-header">
    <div>
      <h3>Security Awareness</h3>

      <p>
        Learn how to identify common phishing indicators.
      </p>
    </div>
  </div>

  <div className="awareness-grid">

    <div className="awareness-card">
      <div className="awareness-icon">🚨</div>
      <h4>Urgent Language</h4>
      <p>
        Be careful when an email creates pressure using urgent
        warnings, account suspension, or immediate action requests.
      </p>
    </div>

    <div className="awareness-card">
      <div className="awareness-icon">🔐</div>
      <h4>Credential Requests</h4>
      <p>
        Never provide passwords, login credentials, or personal
        information through unexpected email requests.
      </p>
    </div>

    <div className="awareness-card">
      <div className="awareness-icon">🔗</div>
      <h4>Suspicious Links</h4>
      <p>
        Check links carefully before clicking. Be cautious of
        unusual domains, suspicious URLs, and deceptive destinations.
      </p>
    </div>

    <div className="awareness-card">
      <div className="awareness-icon">📎</div>
      <h4>Dangerous Attachments</h4>
      <p>
        Avoid opening unexpected executable, script, archive, or
        suspiciously named attachments.
      </p>
    </div>

  </div>
    <div className="before-click">

    <div className="before-click-header">
    

      <div>
        <h3>Before You Click</h3>
        <p>
          Take a quick security check before responding to an unexpected email.
        </p>
      </div>
    </div>

    <div className="checklist-grid">

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Check the Sender</strong>
          <p>Inspect the complete sender address, not just the display name.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Verify the Domain</strong>
          <p>Look for unusual spelling, unexpected domains, or suspicious subdomains.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Question Urgency</strong>
          <p>Be cautious when a message pressures you to act immediately.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Inspect Links</strong>
          <p>Check the actual destination before clicking an unexpected link.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Protect Credentials</strong>
          <p>Never provide passwords or sensitive information through unexpected requests.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Check Attachments</strong>
          <p>Be careful with unexpected executable, script, archive, or suspicious files.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Watch Generic Greetings</strong>
          <p>Generic greetings can be one indicator when combined with other warning signs.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Verify Payment Requests</strong>
          <p>Confirm unexpected financial requests through an independent trusted channel.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Notice Threatening Language</strong>
          <p>Account suspension or threatening messages can be used to create pressure.</p>
        </div>
      </div>

      <div className="checklist-item">
        <span>✓</span>
        <div>
          <strong>Consider the Context</strong>
          <p>Ask whether you expected the message and whether the request makes sense.</p>
        </div>
      </div>

    </div>

  </div>

</section>

      </main>

    </div>
  )
}

export default App