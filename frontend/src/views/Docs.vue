<script setup>
import { ref, computed } from 'vue'
import { useI18n } from '../i18n'

const { t, lang } = useI18n()
const activeTab = ref('getting-started')
const searchQuery = ref('')
const expandedScanner = ref(null)
const expandedFaq = ref(null)

const tabs = [
  { id: 'getting-started', icon: '\u{1F680}' },
  { id: 'scanners', icon: '\u{1F50D}' },
  { id: 'scoring', icon: '\u{1F4CA}' },
  { id: 'reports', icon: '\u{1F4C4}' },
  { id: 'api', icon: '\u{1F50C}' },
  { id: 'integrations', icon: '\u{1F517}' },
  { id: 'faq', icon: '\u{2753}' },
]

const gettingStartedSteps = [
  {
    num: 1,
    title: { en: 'Add Your Website', ar: '\u0623\u0636\u0641 \u0645\u0648\u0642\u0639\u0643' },
    desc: { en: 'Navigate to the Targets page and click "Add Target". Enter your website URL (e.g., https://example.edu.iq). You can add up to 5 websites on the free plan.', ar: '\u0627\u0646\u062A\u0642\u0644 \u0625\u0644\u0649 \u0635\u0641\u062D\u0629 \u0627\u0644\u0645\u0648\u0627\u0642\u0639 \u0648\u0627\u0636\u063A\u0637 "\u0625\u0636\u0627\u0641\u0629 \u0645\u0648\u0642\u0639". \u0623\u062F\u062E\u0644 \u0631\u0627\u0628\u0637 \u0645\u0648\u0642\u0639\u0643. \u064A\u0645\u0643\u0646\u0643 \u0625\u0636\u0627\u0641\u0629 \u062D\u062A\u0649 5 \u0645\u0648\u0627\u0642\u0639 \u0641\u064A \u0627\u0644\u062E\u0637\u0629 \u0627\u0644\u0645\u062C\u0627\u0646\u064A\u0629.' },
    icon: '\u{1F310}'
  },
  {
    num: 2,
    title: { en: 'Verify Domain Ownership', ar: '\u0623\u062B\u0628\u062A \u0645\u0644\u0643\u064A\u0629 \u0627\u0644\u0646\u0637\u0627\u0642' },
    desc: { en: 'Add a TXT record to your DNS settings with the verification code shown. This proves you own the domain. Wait for DNS propagation (up to 24h), then click "Check Verification".', ar: '\u0623\u0636\u0641 \u0633\u062C\u0644 TXT \u0625\u0644\u0649 \u0625\u0639\u062F\u0627\u062F\u0627\u062A DNS \u0628\u0631\u0645\u0632 \u0627\u0644\u062A\u062D\u0642\u0642. \u0627\u0646\u062A\u0638\u0631 \u0627\u0646\u062A\u0634\u0627\u0631 DNS (\u062D\u062A\u0649 24 \u0633\u0627\u0639\u0629)\u060C \u062B\u0645 \u0627\u0636\u063A\u0637 "\u062A\u062D\u0642\u0642 \u0627\u0644\u0622\u0646".' },
    icon: '\u2705'
  },
  {
    num: 3,
    title: { en: 'Run Your First Scan', ar: '\u0634\u063A\u0651\u0644 \u0623\u0648\u0644 \u0641\u062D\u0635' },
    desc: { en: 'Go to Scans page, click "Start New Scan", select your targets and scan policy. Light (8 categories, 30s), Standard (16, 60s), or Deep (25, 120s).', ar: '\u0627\u0630\u0647\u0628 \u0625\u0644\u0649 \u0635\u0641\u062D\u0629 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A\u060C \u0627\u0636\u063A\u0637 "\u0628\u062F\u0621 \u0641\u062D\u0635 \u062C\u062F\u064A\u062F"\u060C \u0627\u062E\u062A\u0631 \u0627\u0644\u0645\u0648\u0627\u0642\u0639 \u0648\u0633\u064A\u0627\u0633\u0629 \u0627\u0644\u0641\u062D\u0635.' },
    icon: '\u{1F50D}'
  },
  {
    num: 4,
    title: { en: 'View Results & Download Report', ar: '\u0627\u0639\u0631\u0636 \u0627\u0644\u0646\u062A\u0627\u0626\u062C \u0648\u062D\u0645\u0651\u0644 \u0627\u0644\u062A\u0642\u0631\u064A\u0631' },
    desc: { en: 'Once the scan completes, view detailed results. Download PDF reports, run AI analysis for fix recommendations, and track your score over time.', ar: '\u0628\u0639\u062F \u0627\u0643\u062A\u0645\u0627\u0644 \u0627\u0644\u0641\u062D\u0635\u060C \u0627\u0639\u0631\u0636 \u0627\u0644\u0646\u062A\u0627\u0626\u062C. \u062D\u0645\u0651\u0644 \u062A\u0642\u0627\u0631\u064A\u0631 PDF\u060C \u0634\u063A\u0651\u0644 \u062A\u062D\u0644\u064A\u0644 AI\u060C \u0648\u062A\u0627\u0628\u0639 \u062F\u0631\u062C\u062A\u0643 \u0639\u0628\u0631 \u0627\u0644\u0632\u0645\u0646.' },
    icon: '\u{1F4CA}'
  },
]

const confidenceLevels = [
  { pct: '100%', label: { en: 'Deterministic', ar: '\u062D\u062A\u0645\u064A' } },
  { pct: '85-95%', label: { en: 'High Confidence', ar: '\u062B\u0642\u0629 \u0639\u0627\u0644\u064A\u0629' } },
  { pct: '70-80%', label: { en: 'Medium Confidence', ar: '\u062B\u0642\u0629 \u0645\u062A\u0648\u0633\u0637\u0629' } },
  { pct: '60%', label: { en: 'Lower Confidence', ar: '\u062B\u0642\u0629 \u0623\u0642\u0644' } },
]

const scanPoliciesData = [
  { name: { en: 'Light', ar: '\u062E\u0641\u064A\u0641' }, cats: 8, timeout: '30s', desc: { en: 'Quick security check: ssl, headers, cookies, mixed_content, performance, dns, seo, content', ar: '\u0641\u062D\u0635 \u0633\u0631\u064A\u0639: ssl\u060C headers\u060C cookies\u060C mixed_content\u060C performance\u060C dns\u060C seo\u060C content' } },
  { name: { en: 'Standard', ar: '\u0642\u064A\u0627\u0633\u064A' }, cats: 16, timeout: '60s', desc: { en: 'Comprehensive audit: adds server_info, directory, ddos, cors, http_methods, info_disclosure, hosting, secrets', ar: '\u0641\u062D\u0635 \u0634\u0627\u0645\u0644: \u064A\u0636\u064A\u0641 server_info\u060C directory\u060C ddos\u060C cors\u060C http_methods\u060C info_disclosure\u060C hosting\u060C secrets' } },
  { name: { en: 'Deep', ar: '\u0639\u0645\u064A\u0642' }, cats: 36, timeout: '180s', desc: { en: 'Full assessment: all 36 scanners including WordPress Deep Security, plugin/theme CVEs, backup files, JS secrets, CMS CVEs, SQLi, SSRF, and more', ar: '\u062A\u0642\u064A\u064A\u0645 \u0643\u0627\u0645\u0644: \u062C\u0645\u064A\u0639 \u0627\u0644\u0640 25 \u0641\u0627\u062D\u0635 \u0628\u0645\u0627 \u0641\u064A\u0647\u0627 malware\u060C xss\u060C wordpress\u060C subdomains\u060C \u0648\u0627\u0644\u0645\u0632\u064A\u062F' } },
]

const reportsData = [
  {
    icon: '\u{1F4D1}', title: { en: 'PDF Report', ar: '\u062A\u0642\u0631\u064A\u0631 PDF' },
    desc: {
      en: 'Comprehensive PDF report including: overall score with grade, category-by-category breakdown, individual check details with pass/fail status, OWASP Top 10 compliance mapping, remediation recommendations, score history chart, and executive summary.',
      ar: '\u062A\u0642\u0631\u064A\u0631 PDF \u0634\u0627\u0645\u0644 \u064A\u062A\u0636\u0645\u0646: \u0627\u0644\u062F\u0631\u062C\u0629 \u0627\u0644\u0625\u062C\u0645\u0627\u0644\u064A\u0629 \u0645\u0639 \u0627\u0644\u062A\u0642\u062F\u064A\u0631\u060C \u062A\u0641\u0635\u064A\u0644 \u0643\u0644 \u0641\u0626\u0629\u060C \u062A\u0641\u0627\u0635\u064A\u0644 \u0643\u0644 \u0641\u062D\u0635 \u0645\u0639 \u062D\u0627\u0644\u0629 \u0627\u0644\u0646\u062C\u0627\u062D/\u0627\u0644\u0641\u0634\u0644\u060C \u062E\u0631\u064A\u0637\u0629 \u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0645\u0639 OWASP Top 10\u060C \u062A\u0648\u0635\u064A\u0627\u062A \u0627\u0644\u0625\u0635\u0644\u0627\u062D\u060C \u0631\u0633\u0645 \u062A\u0627\u0631\u064A\u062E \u0627\u0644\u062F\u0631\u062C\u0627\u062A\u060C \u0648\u0645\u0644\u062E\u0635 \u062A\u0646\u0641\u064A\u0630\u064A.'
    },
    how: { en: 'Click "Download PDF" on any scan result page.', ar: '\u0627\u0636\u063A\u0637 "\u062A\u062D\u0645\u064A\u0644 PDF" \u0641\u064A \u0623\u064A \u0635\u0641\u062D\u0629 \u0646\u062A\u0627\u0626\u062C \u0641\u062D\u0635.' }
  },
  {
    icon: '\u{1F4CA}', title: { en: 'CSV Export', ar: '\u062A\u0635\u062F\u064A\u0631 CSV' },
    desc: {
      en: 'Export scan data as CSV for spreadsheet analysis in Excel, Google Sheets, or other tools. Includes all check names, scores, statuses, and OWASP/CWE mappings.',
      ar: '\u062A\u0635\u062F\u064A\u0631 \u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0641\u062D\u0635 \u0643 CSV \u0644\u062A\u062D\u0644\u064A\u0644 \u0627\u0644\u062C\u062F\u0627\u0648\u0644 \u0641\u064A Excel \u0623\u0648 Google Sheets. \u064A\u062A\u0636\u0645\u0646 \u062C\u0645\u064A\u0639 \u0623\u0633\u0645\u0627\u0621 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0648\u0627\u0644\u062F\u0631\u062C\u0627\u062A \u0648\u0627\u0644\u062D\u0627\u0644\u0627\u062A \u0648\u062A\u0639\u064A\u064A\u0646\u0627\u062A OWASP/CWE.'
    },
    how: { en: 'Available in the scan results export menu.', ar: '\u0645\u062A\u0627\u062D \u0641\u064A \u0642\u0627\u0626\u0645\u0629 \u062A\u0635\u062F\u064A\u0631 \u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0641\u062D\u0635.' }
  },
  {
    icon: '\u{1F4BB}', title: { en: 'SARIF Export', ar: '\u062A\u0635\u062F\u064A\u0631 SARIF' },
    desc: {
      en: 'Static Analysis Results Interchange Format (SARIF) for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other SAST tools.',
      ar: '\u0635\u064A\u063A\u0629 SARIF \u0644\u0644\u062A\u0643\u0627\u0645\u0644 \u0645\u0639 GitHub Code Scanning \u0648VS Code SARIF Viewer \u0648\u0623\u062F\u0648\u0627\u062A SAST \u0627\u0644\u0623\u062E\u0631\u0649.'
    },
    how: { en: 'Export from the scan results page or via API.', ar: '\u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u0645\u0646 \u0635\u0641\u062D\u0629 \u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0641\u062D\u0635 \u0623\u0648 \u0639\u0628\u0631 API.' }
  },
  {
    icon: '\u{1F916}', title: { en: 'AI Analysis', ar: '\u062A\u062D\u0644\u064A\u0644 AI' },
    desc: {
      en: 'AI-powered analysis using your configured LLM provider (DeepSeek, OpenAI, Anthropic, etc.). Provides: executive summary, detailed fix instructions, step-by-step roadmap to improve, and code examples for server configuration.',
      ar: '\u062A\u062D\u0644\u064A\u0644 \u0645\u062F\u0639\u0648\u0645 \u0628\u0627\u0644\u0630\u0643\u0627\u0621 \u0627\u0644\u0627\u0635\u0637\u0646\u0627\u0639\u064A \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0645\u0632\u0648\u062F LLM \u0627\u0644\u0645\u0647\u064A\u0623. \u064A\u0642\u062F\u0645: \u0645\u0644\u062E\u0635 \u062A\u0646\u0641\u064A\u0630\u064A\u060C \u062A\u0639\u0644\u064A\u0645\u0627\u062A \u0625\u0635\u0644\u0627\u062D \u0645\u0641\u0635\u0644\u0629\u060C \u062E\u0627\u0631\u0637\u0629 \u0637\u0631\u064A\u0642 \u0644\u0644\u062A\u062D\u0633\u064A\u0646\u060C \u0648\u0623\u0645\u062B\u0644\u0629 \u0623\u0643\u0648\u0627\u062F \u0644\u0625\u0639\u062F\u0627\u062F \u0627\u0644\u062E\u0627\u062F\u0645.'
    },
    how: { en: 'Click "AI Analysis" on any result page. Requires AI provider configuration in Settings.', ar: '\u0627\u0636\u063A\u0637 "\u062A\u062D\u0644\u064A\u0644 AI" \u0641\u064A \u0623\u064A \u0635\u0641\u062D\u0629 \u0646\u062A\u0627\u0626\u062C. \u064A\u062A\u0637\u0644\u0628 \u062A\u0647\u064A\u0626\u0629 \u0645\u0632\u0648\u062F AI \u0641\u064A \u0627\u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A.' }
  },
  {
    icon: '\u{1F6E1}\uFE0F', title: { en: 'OWASP Compliance Report', ar: '\u062A\u0642\u0631\u064A\u0631 \u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0645\u0639 OWASP' },
    desc: {
      en: 'Maps all scan findings to the OWASP Top 10 2021 categories (A01-A10). Shows compliance percentage per category and which checks passed or failed for each OWASP risk.',
      ar: '\u064A\u0631\u0628\u0637 \u062C\u0645\u064A\u0639 \u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0641\u062D\u0635 \u0628\u0641\u0626\u0627\u062A OWASP Top 10 2021 (A01-A10). \u064A\u0639\u0631\u0636 \u0646\u0633\u0628\u0629 \u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0644\u0643\u0644 \u0641\u0626\u0629 \u0648\u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0627\u0644\u0646\u0627\u062C\u062D\u0629 \u0648\u0627\u0644\u0641\u0627\u0634\u0644\u0629 \u0644\u0643\u0644 \u062E\u0637\u0631.'
    },
    how: { en: 'Available in the scan result detail page under the Compliance tab.', ar: '\u0645\u062A\u0627\u062D \u0641\u064A \u0635\u0641\u062D\u0629 \u062A\u0641\u0627\u0635\u064A\u0644 \u0646\u062A\u064A\u062C\u0629 \u0627\u0644\u0641\u062D\u0635 \u062A\u062D\u062A \u062A\u0628\u0648\u064A\u0628 \u0627\u0644\u062A\u0648\u0627\u0641\u0642.' }
  },
]

const rateLimitsData = [
  { plan: { en: 'Free', ar: '\u0645\u062C\u0627\u0646\u064A' }, limit: '60 req/min' },
  { plan: { en: 'Basic', ar: '\u0623\u0633\u0627\u0633\u064A' }, limit: '120 req/min' },
  { plan: { en: 'Pro', ar: '\u0627\u062D\u062A\u0631\u0627\u0641\u064A' }, limit: '300 req/min' },
  { plan: { en: 'Enterprise', ar: '\u0645\u0624\u0633\u0633\u0627\u062A' }, limit: '1000 req/min' },
]

const integrationsData = [
  {
    icon: '\u{1F514}', title: { en: 'Webhooks', ar: '\u0627\u0644\u0648\u064A\u0628\u0647\u0648\u0643' },
    desc: {
      en: 'Send scan results to Slack, Telegram, Discord, or any custom URL. Configure webhook endpoints in the Webhooks page. Supports JSON payloads with scan summary, scores, and detailed findings.',
      ar: '\u0623\u0631\u0633\u0644 \u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0641\u062D\u0635 \u0625\u0644\u0649 Slack\u060C Telegram\u060C Discord\u060C \u0623\u0648 \u0623\u064A URL \u0645\u062E\u0635\u0635. \u0647\u064A\u0651\u0626 \u0646\u0642\u0627\u0637 \u0627\u0644\u0648\u064A\u0628\u0647\u0648\u0643 \u0641\u064A \u0635\u0641\u062D\u0629 \u0627\u0644\u0625\u0634\u0639\u0627\u0631\u0627\u062A. \u064A\u062F\u0639\u0645 \u062D\u0645\u0648\u0644\u0627\u062A JSON \u0645\u0639 \u0645\u0644\u062E\u0635 \u0627\u0644\u0641\u062D\u0635 \u0648\u0627\u0644\u062F\u0631\u062C\u0627\u062A \u0648\u0627\u0644\u0646\u062A\u0627\u0626\u062C \u0627\u0644\u062A\u0641\u0635\u064A\u0644\u064A\u0629.'
    }
  },
  {
    icon: '\u{1F4E7}', title: { en: 'Email Alerts', ar: '\u062A\u0646\u0628\u064A\u0647\u0627\u062A \u0627\u0644\u0628\u0631\u064A\u062F' },
    desc: {
      en: 'Receive email notifications when scans complete. Configure SMTP settings for custom email delivery. Alert types: scan completion, score drop below threshold, scheduled scan failures.',
      ar: '\u0627\u0633\u062A\u0644\u0645 \u0625\u0634\u0639\u0627\u0631\u0627\u062A \u0628\u0631\u064A\u062F \u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0639\u0646\u062F \u0627\u0643\u062A\u0645\u0627\u0644 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A. \u0647\u064A\u0651\u0626 \u0625\u0639\u062F\u0627\u062F\u0627\u062A SMTP \u0644\u062A\u0633\u0644\u064A\u0645 \u0628\u0631\u064A\u062F \u0645\u062E\u0635\u0635. \u0623\u0646\u0648\u0627\u0639 \u0627\u0644\u062A\u0646\u0628\u064A\u0647\u0627\u062A: \u0627\u0643\u062A\u0645\u0627\u0644 \u0627\u0644\u0641\u062D\u0635\u060C \u0627\u0646\u062E\u0641\u0627\u0636 \u0627\u0644\u062F\u0631\u062C\u0629\u060C \u0641\u0634\u0644 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0627\u0644\u0645\u062C\u062F\u0648\u0644\u0629.'
    }
  },
  {
    icon: '\u{1F4BB}', title: { en: 'GitHub Actions', ar: 'GitHub Actions' },
    desc: {
      en: 'Integrate Seku into your CI/CD pipeline. Run scans on every deployment and fail the build if security score drops below threshold.',
      ar: '\u0627\u062F\u0645\u062C Seku \u0641\u064A \u062E\u0637 CI/CD \u0627\u0644\u062E\u0627\u0635 \u0628\u0643. \u0634\u063A\u0651\u0644 \u0641\u062D\u0648\u0635\u0627\u062A \u0645\u0639 \u0643\u0644 \u0646\u0634\u0631 \u0648\u0623\u0641\u0634\u0644 \u0627\u0644\u0628\u0646\u0627\u0621 \u0625\u0630\u0627 \u0627\u0646\u062E\u0641\u0636\u062A \u0627\u0644\u062F\u0631\u062C\u0629 \u0639\u0646 \u0627\u0644\u062D\u062F.'
    }
  },
  {
    icon: '\u{1F3AB}', title: { en: 'Jira Integration', ar: '\u062A\u0643\u0627\u0645\u0644 Jira' },
    desc: {
      en: 'Automatically create Jira tickets for failed security checks. Each ticket includes check details, OWASP mapping, remediation steps, and severity level.',
      ar: '\u0623\u0646\u0634\u0626 \u062A\u0630\u0627\u0643\u0631 Jira \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0644\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0627\u0644\u0641\u0627\u0634\u0644\u0629. \u062A\u062A\u0636\u0645\u0646 \u0643\u0644 \u062A\u0630\u0643\u0631\u0629 \u062A\u0641\u0627\u0635\u064A\u0644 \u0627\u0644\u0641\u062D\u0635 \u0648\u062A\u0639\u064A\u064A\u0646 OWASP \u0648\u062E\u0637\u0648\u0627\u062A \u0627\u0644\u0625\u0635\u0644\u0627\u062D \u0648\u0645\u0633\u062A\u0648\u0649 \u0627\u0644\u062E\u0637\u0648\u0631\u0629.'
    }
  },
  {
    icon: '\u{1F41B}', title: { en: 'GitHub Issues', ar: 'GitHub Issues' },
    desc: {
      en: 'Auto-create GitHub Issues for security findings. Issues are labeled with severity and OWASP category. Close issues automatically when the check passes on the next scan.',
      ar: '\u0623\u0646\u0634\u0626 GitHub Issues \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0644\u0644\u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0623\u0645\u0646\u064A\u0629. \u062A\u064F\u0648\u0633\u0645 \u0627\u0644\u0645\u0634\u0643\u0644\u0627\u062A \u0628\u0627\u0644\u062E\u0637\u0648\u0631\u0629 \u0648\u0641\u0626\u0629 OWASP. \u0623\u063A\u0644\u0642 \u0627\u0644\u0645\u0634\u0643\u0644\u0627\u062A \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0639\u0646\u062F \u0646\u062C\u0627\u062D \u0627\u0644\u0641\u062D\u0635 \u0641\u064A \u0627\u0644\u0645\u0631\u0629 \u0627\u0644\u062A\u0627\u0644\u064A\u0629.'
    }
  },
  {
    icon: '\u{2328}\uFE0F', title: { en: 'CLI Tool', ar: '\u0623\u062F\u0627\u0629 \u0633\u0637\u0631 \u0627\u0644\u0623\u0648\u0627\u0645\u0631' },
    desc: {
      en: 'Command-line tool for running scans and retrieving results. Install and use with your API key for automation scripts and CI/CD pipelines.',
      ar: '\u0623\u062F\u0627\u0629 \u0633\u0637\u0631 \u0623\u0648\u0627\u0645\u0631 \u0644\u062A\u0634\u063A\u064A\u0644 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0648\u0627\u0633\u062A\u0631\u062C\u0627\u0639 \u0627\u0644\u0646\u062A\u0627\u0626\u062C. \u062B\u0628\u0651\u062A \u0648\u0627\u0633\u062A\u062E\u062F\u0645 \u0645\u0639 \u0645\u0641\u062A\u0627\u062D API \u0644\u0633\u0643\u0631\u0628\u062A\u0627\u062A \u0627\u0644\u0623\u062A\u0645\u062A\u0629 \u0648\u062E\u0637\u0648\u0637 CI/CD.'
    }
  },
  {
    icon: '\u{1F433}', title: { en: 'Docker', ar: 'Docker' },
    desc: {
      en: 'Run Seku in a Docker container for self-hosted deployments. One-liner command to start scanning your infrastructure.',
      ar: '\u0634\u063A\u0651\u0644 Seku \u0641\u064A \u062D\u0627\u0648\u064A\u0629 Docker \u0644\u0644\u0646\u0634\u0631 \u0627\u0644\u0630\u0627\u062A\u064A. \u0623\u0645\u0631 \u0648\u0627\u062D\u062F \u0644\u0628\u062F\u0621 \u0641\u062D\u0635 \u0628\u0646\u064A\u062A\u0643 \u0627\u0644\u062A\u062D\u062A\u064A\u0629.'
    }
  },
]

const curlSnippet = 'curl -X POST https://your-seku-domain/api/scans \\\n  -H "Authorization: Bearer YOUR_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"target_ids": [1, 2], "policy": "standard"}\''

const pythonSnippet = `import requests

resp = requests.post(
    "https://your-seku-domain/api/scans",
    headers={"X-API-Key": "YOUR_API_KEY"},
    json={"target_ids": [1, 2], "policy": "standard"}
)
print(resp.json())`

const jsSnippet = `const resp = await fetch("https://your-seku-domain/api/scans", {
  method: "POST",
  headers: {
    "X-API-Key": "YOUR_API_KEY",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ target_ids: [1, 2], policy: "standard" }),
});
const data = await resp.json();
console.log(data);`

const ghActionsSnippet = `name: Seku Security Check
on:
  push:
    branches: [main]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Seku
        run: |
          curl -X POST https://your-seku-domain/api/scans \\
            -H "X-API-Key: \${{ secrets.VSCAN_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{ "target_ids": [1], "policy": "standard" }'`

const dockerSnippet = 'docker run -d --name seku -p 8080:8080 \\\n  -e DATABASE_URL=postgres://user:pass@host/vscan \\\n  -e JWT_SECRET=your-secret \\\n  seku:latest'

const tabNames = {
  'getting-started': { en: 'Getting Started', ar: '\u0627\u0644\u0628\u062F\u0621 \u0627\u0644\u0633\u0631\u064A\u0639' },
  'scanners': { en: 'Scanners', ar: '\u0627\u0644\u0641\u0627\u062D\u0635\u0627\u062A' },
  'scoring': { en: 'Scoring System', ar: '\u0646\u0638\u0627\u0645 \u0627\u0644\u062A\u0642\u064A\u064A\u0645' },
  'reports': { en: 'Reports', ar: '\u0627\u0644\u062A\u0642\u0627\u0631\u064A\u0631' },
  'api': { en: 'API Reference', ar: '\u0645\u0631\u062C\u0639 API' },
  'integrations': { en: 'Integrations', ar: '\u0627\u0644\u062A\u0643\u0627\u0645\u0644\u0627\u062A' },
  'faq': { en: 'FAQ', ar: '\u0627\u0644\u0623\u0633\u0626\u0644\u0629 \u0627\u0644\u0634\u0627\u0626\u0639\u0629' },
}

const scanners = [
  {
    id: 'ssl', icon: '\u{1F512}',
    name: { en: 'SSL/TLS', ar: '\u062A\u0634\u0641\u064A\u0631 SSL/TLS' },
    category: 'ssl', weight: 20, checks: 4,
    plans: ['free', 'basic', 'pro', 'enterprise'],
    desc: {
      en: 'HTTPS availability, certificate validity, TLS version, and HTTP-to-HTTPS redirect behavior.',
      ar: '\u062A\u0648\u0641\u0631 HTTPS\u060C \u0635\u0644\u0627\u062D\u064A\u0629 \u0627\u0644\u0634\u0647\u0627\u062F\u0629\u060C \u0625\u0635\u062F\u0627\u0631 TLS\u060C \u0648\u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u0648\u062C\u064A\u0647 \u0645\u0646 HTTP \u0625\u0644\u0649 HTTPS.'
    },
    checksList: [
      { name: { en: 'HTTPS Enabled', ar: '\u062A\u0641\u0639\u064A\u0644 HTTPS' }, owasp: 'A02:2021', cwe: 'CWE-319', cvss: 7.5 },
      { name: { en: 'Certificate Validity', ar: '\u0635\u0644\u0627\u062D\u064A\u0629 \u0627\u0644\u0634\u0647\u0627\u062F\u0629' }, owasp: 'A02:2021', cwe: 'CWE-295', cvss: 5.3 },
      { name: { en: 'TLS Version', ar: '\u0625\u0635\u062F\u0627\u0631 TLS' }, owasp: 'A02:2021', cwe: 'CWE-326', cvss: 7.5 },
      { name: { en: 'HTTP to HTTPS Redirect', ar: '\u062A\u062D\u0648\u064A\u0644 HTTP \u0625\u0644\u0649 HTTPS' }, owasp: 'A02:2021', cwe: 'CWE-319', cvss: 5.3 },
    ]
  },
  {
    id: 'headers', icon: '\u{1F6E1}\uFE0F',
    name: { en: 'Security Headers', ar: '\u0631\u0624\u0648\u0633 \u0627\u0644\u0623\u0645\u0627\u0646' },
    category: 'headers', weight: 20, checks: 7,
    plans: ['free', 'basic', 'pro', 'enterprise'],
    desc: {
      en: 'Essential HTTP security response headers protecting against common web attacks.',
      ar: '\u0631\u0624\u0648\u0633 HTTP \u0627\u0644\u0623\u0645\u0646\u064A\u0629 \u0627\u0644\u0623\u0633\u0627\u0633\u064A\u0629 \u0644\u0644\u062D\u0645\u0627\u064A\u0629 \u0645\u0646 \u0627\u0644\u0647\u062C\u0645\u0627\u062A \u0627\u0644\u0634\u0627\u0626\u0639\u0629.'
    },
    checksList: [
      { name: { en: 'HSTS (Strict-Transport-Security)', ar: 'HSTS (\u0627\u0644\u0646\u0642\u0644 \u0627\u0644\u0635\u0627\u0631\u0645)' }, owasp: 'A05:2021', cwe: 'CWE-523', cvss: 6.1 },
      { name: { en: 'Content Security Policy', ar: '\u0633\u064A\u0627\u0633\u0629 \u0623\u0645\u0627\u0646 \u0627\u0644\u0645\u062D\u062A\u0648\u0649' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 6.1 },
      { name: { en: 'X-Frame-Options', ar: '\u062E\u064A\u0627\u0631\u0627\u062A \u0627\u0644\u0625\u0637\u0627\u0631' }, owasp: 'A01:2021', cwe: 'CWE-1021', cvss: 6.1 },
      { name: { en: 'X-Content-Type-Options', ar: '\u062E\u064A\u0627\u0631\u0627\u062A \u0646\u0648\u0639 \u0627\u0644\u0645\u062D\u062A\u0648\u0649' }, owasp: 'A05:2021', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'X-XSS-Protection', ar: '\u062D\u0645\u0627\u064A\u0629 XSS' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 0 },
      { name: { en: 'Referrer-Policy', ar: '\u0633\u064A\u0627\u0633\u0629 \u0627\u0644\u0645\u0631\u062C\u0639' }, owasp: 'A01:2021', cwe: 'CWE-200', cvss: 0 },
      { name: { en: 'Permissions-Policy', ar: '\u0633\u064A\u0627\u0633\u0629 \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0627\u062A' }, owasp: 'A01:2021', cwe: 'CWE-250', cvss: 4.3 },
    ]
  },
  {
    id: 'cookies', icon: '\u{1F36A}',
    name: { en: 'Cookie Security', ar: '\u0623\u0645\u0627\u0646 \u0627\u0644\u0643\u0648\u0643\u064A\u0632' },
    category: 'cookies', weight: 10, checks: 'Dynamic',
    plans: ['free', 'basic', 'pro', 'enterprise'],
    desc: {
      en: 'Evaluates security attributes (Secure, HttpOnly, SameSite) of all cookies.',
      ar: '\u062A\u0642\u064A\u064A\u0645 \u0633\u0645\u0627\u062A \u0627\u0644\u0623\u0645\u0627\u0646 (Secure\u060C HttpOnly\u060C SameSite) \u0644\u062C\u0645\u064A\u0639 \u0627\u0644\u0643\u0648\u0643\u064A\u0632.'
    },
    checksList: [
      { name: { en: 'Cookie: {name} (per cookie)', ar: '\u0627\u0644\u0643\u0648\u0643\u064A\u0632: {name} (\u0644\u0643\u0644 \u0643\u0648\u0643\u064A)' }, owasp: 'A01:2021', cwe: 'CWE-614', cvss: 0 },
    ]
  },
  {
    id: 'server_info', icon: '\u{1F5A5}\uFE0F',
    name: { en: 'Server Information', ar: '\u0645\u0639\u0644\u0648\u0645\u0627\u062A \u0627\u0644\u062E\u0627\u062F\u0645' },
    category: 'server_info', weight: 15, checks: 3,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Detects server technology exposure through HTTP headers and CMS detection.',
      ar: '\u0643\u0634\u0641 \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u062A\u0642\u0646\u064A\u0629 \u0627\u0644\u062E\u0627\u062F\u0645 \u0639\u0628\u0631 \u0631\u0624\u0648\u0633 HTTP \u0648\u0643\u0634\u0641 \u0646\u0638\u0627\u0645 \u0625\u062F\u0627\u0631\u0629 \u0627\u0644\u0645\u062D\u062A\u0648\u0649.'
    },
    checksList: [
      { name: { en: 'Server Header Exposure', ar: '\u0643\u0634\u0641 \u0631\u0623\u0633 \u0627\u0644\u062E\u0627\u062F\u0645' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 0 },
      { name: { en: 'X-Powered-By Exposure', ar: '\u0643\u0634\u0641 X-Powered-By' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 0 },
      { name: { en: 'CMS Detection', ar: '\u0643\u0634\u0641 \u0646\u0638\u0627\u0645 \u0625\u062F\u0627\u0631\u0629 \u0627\u0644\u0645\u062D\u062A\u0648\u0649' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 0 },
    ]
  },
  {
    id: 'directory', icon: '\u{1F4C2}',
    name: { en: 'Directory Listing', ar: '\u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u0645\u062C\u0644\u062F\u0627\u062A' },
    category: 'directory', weight: 10, checks: 9,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Probes for sensitive files and directories that should not be publicly accessible.',
      ar: '\u0641\u062D\u0635 \u0627\u0644\u0645\u0644\u0641\u0627\u062A \u0648\u0627\u0644\u0645\u062C\u0644\u062F\u0627\u062A \u0627\u0644\u062D\u0633\u0627\u0633\u0629 \u0627\u0644\u062A\u064A \u064A\u062C\u0628 \u0623\u0644\u0627 \u062A\u0643\u0648\u0646 \u0645\u062A\u0627\u062D\u0629 \u0644\u0644\u0639\u0627\u0645\u0629.'
    },
    checksList: [
      { name: { en: 'Robots.txt Exposure', ar: '\u0643\u0634\u0641 Robots.txt' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 0 },
      { name: { en: 'Environment File (.env)', ar: '\u0645\u0644\u0641 \u0627\u0644\u0628\u064A\u0626\u0629 (.env)' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 7.5 },
      { name: { en: 'Git Repository (.git/config)', ar: '\u0645\u0633\u062A\u0648\u062F\u0639 Git' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 7.5 },
      { name: { en: 'PHP Info Exposure', ar: '\u0643\u0634\u0641 PHP Info' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 5.3 },
      { name: { en: 'Admin Panel Exposure', ar: '\u0643\u0634\u0641 \u0644\u0648\u062D\u0629 \u0627\u0644\u0625\u062F\u0627\u0631\u0629' }, owasp: 'A01:2021', cwe: 'CWE-425', cvss: 5.3 },
      { name: { en: 'Backup Directory', ar: '\u0645\u062C\u0644\u062F \u0627\u0644\u0646\u0633\u062E \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 7.5 },
      { name: { en: 'Htaccess File', ar: '\u0645\u0644\u0641 Htaccess' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 5.3 },
      { name: { en: 'WordPress Config Backup', ar: '\u0646\u0633\u062E\u0629 \u0625\u0639\u062F\u0627\u062F\u0627\u062A WordPress' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 7.5 },
      { name: { en: 'Server Status Exposure', ar: '\u0643\u0634\u0641 \u062D\u0627\u0644\u0629 \u0627\u0644\u062E\u0627\u062F\u0645' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 5.3 },
    ]
  },
  {
    id: 'performance', icon: '\u26A1',
    name: { en: 'Performance', ar: '\u0627\u0644\u0623\u062F\u0627\u0621' },
    category: 'performance', weight: 15, checks: 3,
    plans: ['free', 'basic', 'pro', 'enterprise'],
    desc: {
      en: 'Measures response speed, time to first byte (TTFB), and TLS handshake performance.',
      ar: '\u0642\u064A\u0627\u0633 \u0633\u0631\u0639\u0629 \u0627\u0644\u0627\u0633\u062A\u062C\u0627\u0628\u0629 \u0648\u0648\u0642\u062A \u0623\u0648\u0644 \u0628\u0627\u064A\u062A (TTFB) \u0648\u0623\u062F\u0627\u0621 \u0645\u0635\u0627\u0641\u062D\u0629 TLS.'
    },
    checksList: [
      { name: { en: 'Response Time', ar: '\u0648\u0642\u062A \u0627\u0644\u0627\u0633\u062A\u062C\u0627\u0628\u0629' }, owasp: 'A05:2021', cwe: 'CWE-400', cvss: 0 },
      { name: { en: 'Time to First Byte (TTFB)', ar: '\u0648\u0642\u062A \u0623\u0648\u0644 \u0628\u0627\u064A\u062A' }, owasp: 'A05:2021', cwe: 'CWE-400', cvss: 0 },
      { name: { en: 'TLS Handshake Time', ar: '\u0648\u0642\u062A \u0645\u0635\u0627\u0641\u062D\u0629 TLS' }, owasp: 'A05:2021', cwe: 'CWE-400', cvss: 0 },
    ]
  },
  {
    id: 'ddos', icon: '\u{1F6E1}\uFE0F',
    name: { en: 'DDoS Protection', ar: '\u062D\u0645\u0627\u064A\u0629 DDoS' },
    category: 'ddos', weight: 10, checks: 3,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Detects CDN/DDoS protection, rate limiting, and Web Application Firewall (WAF) presence.',
      ar: '\u0643\u0634\u0641 \u062D\u0645\u0627\u064A\u0629 CDN/DDoS\u060C \u062A\u062D\u062F\u064A\u062F \u0627\u0644\u0645\u0639\u062F\u0644\u060C \u0648\u062C\u062F\u0627\u0631 \u062D\u0645\u0627\u064A\u0629 \u0627\u0644\u062A\u0637\u0628\u064A\u0642\u0627\u062A (WAF).'
    },
    checksList: [
      { name: { en: 'CDN/DDoS Protection Service', ar: '\u062E\u062F\u0645\u0629 \u062D\u0645\u0627\u064A\u0629 CDN/DDoS' }, owasp: 'A05:2021', cwe: 'CWE-770', cvss: 0 },
      { name: { en: 'Rate Limiting', ar: '\u062A\u062D\u062F\u064A\u062F \u0627\u0644\u0645\u0639\u062F\u0644' }, owasp: 'A04:2021', cwe: 'CWE-770', cvss: 0 },
      { name: { en: 'Web Application Firewall (WAF)', ar: '\u062C\u062F\u0627\u0631 \u062D\u0645\u0627\u064A\u0629 \u0627\u0644\u062A\u0637\u0628\u064A\u0642\u0627\u062A (WAF)' }, owasp: 'A05:2021', cwe: 'CWE-693', cvss: 0 },
    ]
  },
  {
    id: 'cors', icon: '\u{1F310}',
    name: { en: 'CORS Configuration', ar: '\u0625\u0639\u062F\u0627\u062F\u0627\u062A CORS' },
    category: 'cors', weight: 10, checks: 2,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Evaluates Cross-Origin Resource Sharing configuration for security issues.',
      ar: '\u062A\u0642\u064A\u064A\u0645 \u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0645\u0634\u0627\u0631\u0643\u0629 \u0627\u0644\u0645\u0648\u0627\u0631\u062F \u0639\u0628\u0631 \u0627\u0644\u0623\u0635\u0648\u0644 \u0644\u0644\u0643\u0634\u0641 \u0639\u0646 \u0645\u0634\u0627\u0643\u0644 \u0627\u0644\u0623\u0645\u0627\u0646.'
    },
    checksList: [
      { name: { en: 'CORS Wildcard Origin', ar: '\u0623\u0635\u0644 CORS \u0627\u0644\u0639\u0627\u0645' }, owasp: 'A01:2021', cwe: 'CWE-942', cvss: 7.5 },
      { name: { en: 'CORS Credentials', ar: '\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0639\u062A\u0645\u0627\u062F CORS' }, owasp: 'A01:2021', cwe: 'CWE-942', cvss: 0 },
    ]
  },
  {
    id: 'http_methods', icon: '\u{1F4E1}',
    name: { en: 'HTTP Methods', ar: '\u0637\u0631\u0642 HTTP' },
    category: 'http_methods', weight: 8, checks: 2,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Tests whether dangerous HTTP methods (TRACE, DELETE, PUT) are enabled.',
      ar: '\u0627\u062E\u062A\u0628\u0627\u0631 \u0645\u0627 \u0625\u0630\u0627 \u0643\u0627\u0646\u062A \u0637\u0631\u0642 HTTP \u0627\u0644\u062E\u0637\u064A\u0631\u0629 (TRACE\u060C DELETE\u060C PUT) \u0645\u064F\u0641\u0639\u0651\u0644\u0629.'
    },
    checksList: [
      { name: { en: 'Dangerous HTTP Methods', ar: '\u0637\u0631\u0642 HTTP \u0627\u0644\u062E\u0637\u064A\u0631\u0629' }, owasp: 'A05:2021', cwe: 'CWE-749', cvss: 5.3 },
      { name: { en: 'OPTIONS Method Disclosure', ar: '\u0643\u0634\u0641 \u0637\u0631\u064A\u0642\u0629 OPTIONS' }, owasp: 'A05:2021', cwe: 'CWE-749', cvss: 0 },
    ]
  },
  {
    id: 'dns', icon: '\u{1F4E8}',
    name: { en: 'DNS Security', ar: '\u0623\u0645\u0627\u0646 DNS' },
    category: 'dns', weight: 8, checks: 3,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Evaluates email security DNS records (SPF, DMARC) and certificate authority authorization (CAA).',
      ar: '\u062A\u0642\u064A\u064A\u0645 \u0633\u062C\u0644\u0627\u062A DNS \u0644\u0623\u0645\u0627\u0646 \u0627\u0644\u0628\u0631\u064A\u062F (SPF\u060C DMARC) \u0648\u062A\u0641\u0648\u064A\u0636 \u0633\u0644\u0637\u0629 \u0627\u0644\u0634\u0647\u0627\u062F\u0627\u062A (CAA).'
    },
    checksList: [
      { name: { en: 'SPF Record', ar: '\u0633\u062C\u0644 SPF' }, owasp: 'A07:2021', cwe: 'CWE-290', cvss: 5.3 },
      { name: { en: 'DMARC Record', ar: '\u0633\u062C\u0644 DMARC' }, owasp: 'A07:2021', cwe: 'CWE-290', cvss: 5.3 },
      { name: { en: 'CAA Record', ar: '\u0633\u062C\u0644 CAA' }, owasp: 'A02:2021', cwe: 'CWE-295', cvss: 0 },
    ]
  },
  {
    id: 'mixed_content', icon: '\u{1F504}',
    name: { en: 'Mixed Content', ar: '\u0627\u0644\u0645\u062D\u062A\u0648\u0649 \u0627\u0644\u0645\u062E\u062A\u0644\u0637' },
    category: 'mixed_content', weight: 7, checks: 3,
    plans: ['free', 'basic', 'pro', 'enterprise'],
    desc: {
      en: 'Detects HTTP resources loaded on HTTPS pages (scripts, images, forms).',
      ar: '\u0643\u0634\u0641 \u0645\u0648\u0627\u0631\u062F HTTP \u0627\u0644\u0645\u062D\u0645\u0651\u0644\u0629 \u0639\u0644\u0649 \u0635\u0641\u062D\u0627\u062A HTTPS (\u0633\u0643\u0631\u0628\u062A\u0627\u062A\u060C \u0635\u0648\u0631\u060C \u0646\u0645\u0627\u0630\u062C).'
    },
    checksList: [
      { name: { en: 'Mixed Active Content (Scripts/CSS)', ar: '\u0645\u062D\u062A\u0648\u0649 \u0646\u0634\u0637 \u0645\u062E\u062A\u0644\u0637 (\u0633\u0643\u0631\u0628\u062A\u0627\u062A/CSS)' }, owasp: 'A02:2021', cwe: 'CWE-319', cvss: 0 },
      { name: { en: 'Mixed Passive Content (Images)', ar: '\u0645\u062D\u062A\u0648\u0649 \u0633\u0644\u0628\u064A \u0645\u062E\u062A\u0644\u0637 (\u0635\u0648\u0631)' }, owasp: 'A02:2021', cwe: 'CWE-319', cvss: 0 },
      { name: { en: 'Insecure Form Actions', ar: '\u0625\u062C\u0631\u0627\u0621\u0627\u062A \u0646\u0645\u0627\u0630\u062C \u063A\u064A\u0631 \u0622\u0645\u0646\u0629' }, owasp: 'A02:2021', cwe: 'CWE-319', cvss: 0 },
    ]
  },
  {
    id: 'info_disclosure', icon: '\u{1F4CB}',
    name: { en: 'Information Disclosure', ar: '\u0643\u0634\u0641 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062A' },
    category: 'info_disclosure', weight: 7, checks: 3,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Detects sensitive information in error pages, HTML comments, and technology headers.',
      ar: '\u0643\u0634\u0641 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062A \u0627\u0644\u062D\u0633\u0627\u0633\u0629 \u0641\u064A \u0635\u0641\u062D\u0627\u062A \u0627\u0644\u062E\u0637\u0623 \u0648\u062A\u0639\u0644\u064A\u0642\u0627\u062A HTML \u0648\u0631\u0624\u0648\u0633 \u0627\u0644\u062A\u0642\u0646\u064A\u0629.'
    },
    checksList: [
      { name: { en: 'Error Page Info Disclosure', ar: '\u0643\u0634\u0641 \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u0635\u0641\u062D\u0629 \u0627\u0644\u062E\u0637\u0623' }, owasp: 'A05:2021', cwe: 'CWE-209', cvss: 0 },
      { name: { en: 'Sensitive HTML Comments', ar: '\u062A\u0639\u0644\u064A\u0642\u0627\u062A HTML \u0627\u0644\u062D\u0633\u0627\u0633\u0629' }, owasp: 'A05:2021', cwe: 'CWE-615', cvss: 0 },
      { name: { en: 'Technology Version Disclosure', ar: '\u0643\u0634\u0641 \u0625\u0635\u062F\u0627\u0631\u0627\u062A \u0627\u0644\u062A\u0642\u0646\u064A\u0629' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 0 },
    ]
  },
  {
    id: 'content', icon: '\u{1F4E6}',
    name: { en: 'Content Optimization', ar: '\u062A\u062D\u0633\u064A\u0646 \u0627\u0644\u0645\u062D\u062A\u0648\u0649' },
    category: 'content', weight: 8, checks: 3,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Evaluates caching strategy, page size, and compression effectiveness.',
      ar: '\u062A\u0642\u064A\u064A\u0645 \u0627\u0633\u062A\u0631\u0627\u062A\u064A\u062C\u064A\u0629 \u0627\u0644\u062A\u062E\u0632\u064A\u0646 \u0627\u0644\u0645\u0624\u0642\u062A\u060C \u062D\u062C\u0645 \u0627\u0644\u0635\u0641\u062D\u0629\u060C \u0648\u0641\u0639\u0627\u0644\u064A\u0629 \u0627\u0644\u0636\u063A\u0637.'
    },
    checksList: [
      { name: { en: 'Cache Headers', ar: '\u0631\u0624\u0648\u0633 \u0627\u0644\u062A\u062E\u0632\u064A\u0646 \u0627\u0644\u0645\u0624\u0642\u062A' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'Page Size', ar: '\u062D\u062C\u0645 \u0627\u0644\u0635\u0641\u062D\u0629' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'Compression Ratio', ar: '\u0646\u0633\u0628\u0629 \u0627\u0644\u0636\u063A\u0637' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
    ]
  },
  {
    id: 'hosting', icon: '\u{1F3E2}',
    name: { en: 'Hosting Quality', ar: '\u062C\u0648\u062F\u0629 \u0627\u0644\u0627\u0633\u062A\u0636\u0627\u0641\u0629' },
    category: 'hosting', weight: 12, checks: 6,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Evaluates HTTP/2, HTTP/3, Brotli compression, IPv6, Keep-Alive, and DNS resolution.',
      ar: '\u062A\u0642\u064A\u064A\u0645 HTTP/2\u060C HTTP/3\u060C \u0636\u063A\u0637 Brotli\u060C IPv6\u060C Keep-Alive\u060C \u0648\u062F\u0642\u0629 DNS.'
    },
    checksList: [
      { name: { en: 'HTTP/2 Support', ar: '\u062F\u0639\u0645 HTTP/2' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'HTTP/3 (QUIC) Support', ar: '\u062F\u0639\u0645 HTTP/3 (QUIC)' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'Brotli Compression', ar: '\u0636\u063A\u0637 Brotli' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'IPv6 Support', ar: '\u062F\u0639\u0645 IPv6' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'Keep-Alive', ar: 'Keep-Alive' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'DNS Resolution Time', ar: '\u0648\u0642\u062A \u062F\u0642\u0629 DNS' }, owasp: 'Info', cwe: 'CWE-16', cvss: 0 },
    ]
  },
  {
    id: 'advanced_security', icon: '\u{1F9F1}',
    name: { en: 'Advanced Security', ar: '\u0627\u0644\u0623\u0645\u0627\u0646 \u0627\u0644\u0645\u062A\u0642\u062F\u0645' },
    category: 'advanced_security', weight: 5, checks: 4,
    plans: ['enterprise'],
    desc: {
      en: 'Cross-origin isolation headers (COEP, COOP, CORP) and OCSP Stapling.',
      ar: '\u0631\u0624\u0648\u0633 \u0627\u0644\u0639\u0632\u0644 \u0639\u0628\u0631 \u0627\u0644\u0623\u0635\u0648\u0644 (COEP\u060C COOP\u060C CORP) \u0648OCSP Stapling.'
    },
    checksList: [
      { name: { en: 'Cross-Origin-Embedder-Policy (COEP)', ar: 'COEP' }, owasp: 'A01:2021', cwe: 'CWE-346', cvss: 0 },
      { name: { en: 'Cross-Origin-Opener-Policy (COOP)', ar: 'COOP' }, owasp: 'A01:2021', cwe: 'CWE-346', cvss: 0 },
      { name: { en: 'Cross-Origin-Resource-Policy (CORP)', ar: 'CORP' }, owasp: 'A01:2021', cwe: 'CWE-346', cvss: 0 },
      { name: { en: 'OCSP Stapling', ar: 'OCSP Stapling' }, owasp: 'A02:2021', cwe: 'CWE-299', cvss: 0 },
    ]
  },
  {
    id: 'malware', icon: '\u{1F41B}',
    name: { en: 'Malware & Threats', ar: '\u0627\u0644\u0628\u0631\u0645\u062C\u064A\u0627\u062A \u0627\u0644\u062E\u0628\u064A\u062B\u0629' },
    category: 'malware', weight: 10, checks: 6,
    plans: ['enterprise'],
    desc: {
      en: 'Detects malicious JavaScript, hidden iframes, crypto miners, suspicious redirects, and malware signatures.',
      ar: '\u0643\u0634\u0641 JavaScript \u0627\u0644\u062E\u0628\u064A\u062B\u060C \u0625\u0637\u0627\u0631\u0627\u062A iframe \u0627\u0644\u0645\u062E\u0641\u064A\u0629\u060C \u0645\u064F\u0639\u062F\u0651\u0646\u0627\u062A \u0627\u0644\u0639\u0645\u0644\u0627\u062A\u060C \u0648\u0627\u0644\u062A\u0648\u062C\u064A\u0647\u0627\u062A \u0627\u0644\u0645\u0634\u0628\u0648\u0647\u0629.'
    },
    checksList: [
      { name: { en: 'Malicious JavaScript', ar: 'JavaScript \u062E\u0628\u064A\u062B' }, owasp: 'A03:2021', cwe: 'CWE-94', cvss: 9.8 },
      { name: { en: 'Hidden Iframes', ar: '\u0625\u0637\u0627\u0631\u0627\u062A \u0645\u062E\u0641\u064A\u0629' }, owasp: 'A03:2021', cwe: 'CWE-829', cvss: 8.8 },
      { name: { en: 'Cryptocurrency Miners', ar: '\u0645\u064F\u0639\u062F\u0651\u0646\u0627\u062A \u0627\u0644\u0639\u0645\u0644\u0627\u062A' }, owasp: 'A03:2021', cwe: 'CWE-506', cvss: 7.5 },
      { name: { en: 'Suspicious Redirects', ar: '\u062A\u0648\u062C\u064A\u0647\u0627\u062A \u0645\u0634\u0628\u0648\u0647\u0629' }, owasp: 'A01:2021', cwe: 'CWE-601', cvss: 0 },
      { name: { en: 'Malware Signatures', ar: '\u062A\u0648\u0642\u064A\u0639\u0627\u062A \u0627\u0644\u0628\u0631\u0645\u062C\u064A\u0627\u062A \u0627\u0644\u062E\u0628\u064A\u062B\u0629' }, owasp: 'A03:2021', cwe: 'CWE-506', cvss: 0 },
      { name: { en: 'Malicious External Links', ar: '\u0631\u0648\u0627\u0628\u0637 \u062E\u0627\u0631\u062C\u064A\u0629 \u062E\u0628\u064A\u062B\u0629' }, owasp: 'A03:2021', cwe: 'CWE-829', cvss: 0 },
    ]
  },
  {
    id: 'threat_intel', icon: '\u{1F575}\uFE0F',
    name: { en: 'Threat Intelligence', ar: '\u0627\u0633\u062A\u062E\u0628\u0627\u0631\u0627\u062A \u0627\u0644\u062A\u0647\u062F\u064A\u062F\u0627\u062A' },
    category: 'threat_intel', weight: 8, checks: 4,
    plans: ['enterprise'],
    desc: {
      en: 'Cryptojacking detection, C2 server communication, DNS blacklists, and domain reputation.',
      ar: '\u0643\u0634\u0641 \u0627\u0644\u062A\u0639\u062F\u064A\u0646 \u0627\u0644\u062E\u0641\u064A\u060C \u0627\u062A\u0635\u0627\u0644\u0627\u062A C2\u060C \u0642\u0648\u0627\u0626\u0645 DNS \u0627\u0644\u0633\u0648\u062F\u0627\u0621\u060C \u0648\u0633\u0645\u0639\u0629 \u0627\u0644\u0646\u0637\u0627\u0642.'
    },
    checksList: [
      { name: { en: 'Cryptojacking Detection', ar: '\u0643\u0634\u0641 \u0627\u0644\u062A\u0639\u062F\u064A\u0646 \u0627\u0644\u062E\u0641\u064A' }, owasp: 'A03:2021', cwe: 'CWE-506', cvss: 0 },
      { name: { en: 'C2 Server Communication', ar: '\u0627\u062A\u0635\u0627\u0644\u0627\u062A \u062E\u0627\u062F\u0645 C2' }, owasp: 'A03:2021', cwe: 'CWE-506', cvss: 0 },
      { name: { en: 'Blacklist Check', ar: '\u0641\u062D\u0635 \u0627\u0644\u0642\u0648\u0627\u0626\u0645 \u0627\u0644\u0633\u0648\u062F\u0627\u0621' }, owasp: 'A07:2021', cwe: 'CWE-290', cvss: 0 },
      { name: { en: 'Domain Reputation & Age', ar: '\u0633\u0645\u0639\u0629 \u0627\u0644\u0646\u0637\u0627\u0642 \u0648\u0639\u0645\u0631\u0647' }, owasp: 'A07:2021', cwe: 'CWE-290', cvss: 0 },
    ]
  },
  {
    id: 'seo', icon: '\u{1F4C8}',
    name: { en: 'SEO & Technical Health', ar: 'SEO \u0648\u0627\u0644\u0635\u062D\u0629 \u0627\u0644\u062A\u0642\u0646\u064A\u0629' },
    category: 'seo', weight: 7, checks: 6,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Meta tags, Open Graph, sitemap, robots.txt, structured data, and mobile friendliness.',
      ar: '\u0627\u0644\u0648\u0633\u0648\u0645 \u0627\u0644\u0648\u0635\u0641\u064A\u0629\u060C Open Graph\u060C \u062E\u0631\u064A\u0637\u0629 \u0627\u0644\u0645\u0648\u0642\u0639\u060C robots.txt\u060C \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u0647\u064A\u0643\u0644\u0629\u060C \u0648\u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0645\u0639 \u0627\u0644\u062C\u0648\u0627\u0644.'
    },
    checksList: [
      { name: { en: 'Meta Tags Quality', ar: '\u062C\u0648\u062F\u0629 \u0627\u0644\u0648\u0633\u0648\u0645 \u0627\u0644\u0648\u0635\u0641\u064A\u0629' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'Open Graph Tags', ar: '\u0648\u0633\u0648\u0645 Open Graph' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'Sitemap Accessibility', ar: '\u0625\u0645\u0643\u0627\u0646\u064A\u0629 \u0627\u0644\u0648\u0635\u0648\u0644 \u0644\u062E\u0631\u064A\u0637\u0629 \u0627\u0644\u0645\u0648\u0642\u0639' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'Robots.txt Quality', ar: '\u062C\u0648\u062F\u0629 Robots.txt' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'Structured Data', ar: '\u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u0647\u064A\u0643\u0644\u0629' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'Mobile Friendliness', ar: '\u0627\u0644\u062A\u0648\u0627\u0641\u0642 \u0645\u0639 \u0627\u0644\u062C\u0648\u0627\u0644' }, owasp: 'Info', cwe: '-', cvss: 0 },
    ]
  },
  {
    id: 'third_party', icon: '\u{1F9E9}',
    name: { en: 'Third-Party Scripts', ar: '\u0627\u0644\u0633\u0643\u0631\u0628\u062A\u0627\u062A \u0627\u0644\u062E\u0627\u0631\u062C\u064A\u0629' },
    category: 'third_party', weight: 6, checks: 4,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Evaluates risk of external JavaScript/CSS dependencies and SRI coverage.',
      ar: '\u062A\u0642\u064A\u064A\u0645 \u0645\u062E\u0627\u0637\u0631 \u0627\u0644\u0627\u0639\u062A\u0645\u0627\u062F\u064A\u0627\u062A \u0627\u0644\u062E\u0627\u0631\u062C\u064A\u0629 \u0644\u0640 JavaScript/CSS \u0648\u062A\u063A\u0637\u064A\u0629 SRI.'
    },
    checksList: [
      { name: { en: 'External Script Count', ar: '\u0639\u062F\u062F \u0627\u0644\u0633\u0643\u0631\u0628\u062A\u0627\u062A \u0627\u0644\u062E\u0627\u0631\u062C\u064A\u0629' }, owasp: 'A08:2021', cwe: 'CWE-829', cvss: 0 },
      { name: { en: 'Subresource Integrity (SRI)', ar: '\u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u0645\u0648\u0627\u0631\u062F \u0627\u0644\u0641\u0631\u0639\u064A\u0629 (SRI)' }, owasp: 'A08:2021', cwe: 'CWE-353', cvss: 0 },
      { name: { en: 'Trusted Sources', ar: '\u0627\u0644\u0645\u0635\u0627\u062F\u0631 \u0627\u0644\u0645\u0648\u062B\u0648\u0642\u0629' }, owasp: 'A08:2021', cwe: 'CWE-829', cvss: 0 },
      { name: { en: 'External CSS Count', ar: '\u0639\u062F\u062F CSS \u0627\u0644\u062E\u0627\u0631\u062C\u064A' }, owasp: 'A08:2021', cwe: 'CWE-829', cvss: 0 },
    ]
  },
  {
    id: 'js_libraries', icon: '\u{1F4DA}',
    name: { en: 'JavaScript Libraries', ar: '\u0645\u0643\u062A\u0628\u0627\u062A JavaScript' },
    category: 'js_libraries', weight: 6, checks: 3,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Detects outdated and vulnerable JavaScript libraries (jQuery, AngularJS, Bootstrap, etc.).',
      ar: '\u0643\u0634\u0641 \u0645\u0643\u062A\u0628\u0627\u062A JavaScript \u0627\u0644\u0642\u062F\u064A\u0645\u0629 \u0648\u0627\u0644\u0645\u0639\u0631\u0636\u0629 \u0644\u0644\u062B\u063A\u0631\u0627\u062A (jQuery\u060C AngularJS\u060C Bootstrap).'
    },
    checksList: [
      { name: { en: 'Outdated jQuery Detection', ar: '\u0643\u0634\u0641 jQuery \u0627\u0644\u0642\u062F\u064A\u0645' }, owasp: 'A06:2021', cwe: 'CWE-1104', cvss: 0 },
      { name: { en: 'Known Vulnerable Libraries', ar: '\u0645\u0643\u062A\u0628\u0627\u062A \u0645\u0639\u0631\u0648\u0641\u0629 \u0627\u0644\u062B\u063A\u0631\u0627\u062A' }, owasp: 'A06:2021', cwe: 'CWE-1104', cvss: 0 },
      { name: { en: 'Inline Script Analysis', ar: '\u062A\u062D\u0644\u064A\u0644 \u0627\u0644\u0633\u0643\u0631\u0628\u062A\u0627\u062A \u0627\u0644\u0645\u0636\u0645\u0651\u0646\u0629' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 0 },
    ]
  },
  {
    id: 'wordpress', icon: '\u{1F4DD}',
    name: { en: 'WordPress Security', ar: '\u0623\u0645\u0627\u0646 WordPress' },
    category: 'wordpress', weight: 8, checks: 6,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Specialized WordPress checks: version, login page, XML-RPC, REST API, debug mode.',
      ar: '\u0641\u062D\u0648\u0635\u0627\u062A WordPress \u0627\u0644\u0645\u062A\u062E\u0635\u0635\u0629: \u0627\u0644\u0625\u0635\u062F\u0627\u0631\u060C \u0635\u0641\u062D\u0629 \u0627\u0644\u062F\u062E\u0648\u0644\u060C XML-RPC\u060C REST API\u060C \u0648\u0636\u0639 \u0627\u0644\u062A\u0635\u062D\u064A\u062D.'
    },
    checksList: [
      { name: { en: 'WordPress Version', ar: '\u0625\u0635\u062F\u0627\u0631 WordPress' }, owasp: 'A06:2021', cwe: 'CWE-1104', cvss: 0 },
      { name: { en: 'Login Page Exposure', ar: '\u0643\u0634\u0641 \u0635\u0641\u062D\u0629 \u0627\u0644\u062F\u062E\u0648\u0644' }, owasp: 'A07:2021', cwe: 'CWE-307', cvss: 0 },
      { name: { en: 'XML-RPC Exposure', ar: '\u0643\u0634\u0641 XML-RPC' }, owasp: 'A05:2021', cwe: 'CWE-749', cvss: 0 },
      { name: { en: 'REST API User Enumeration', ar: '\u062A\u0639\u062F\u0627\u062F \u0645\u0633\u062A\u062E\u062F\u0645\u064A REST API' }, owasp: 'A01:2021', cwe: 'CWE-200', cvss: 0 },
      { name: { en: 'Readme/License Exposure', ar: '\u0643\u0634\u0641 Readme/License' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 0 },
      { name: { en: 'Debug Mode', ar: '\u0648\u0636\u0639 \u0627\u0644\u062A\u0635\u062D\u064A\u062D' }, owasp: 'A05:2021', cwe: 'CWE-209', cvss: 0 },
    ]
  },
  {
    id: 'xss', icon: '\u{1F489}',
    name: { en: 'XSS Vulnerability', ar: '\u062B\u063A\u0631\u0627\u062A XSS' },
    category: 'xss', weight: 9, checks: 5,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Safe, non-destructive XSS detection using canary-based reflection analysis.',
      ar: '\u0643\u0634\u0641 XSS \u0622\u0645\u0646 \u0648\u063A\u064A\u0631 \u0645\u062F\u0645\u0631 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u062A\u062D\u0644\u064A\u0644 \u0627\u0644\u0627\u0646\u0639\u0643\u0627\u0633 \u0628\u0627\u0644\u0639\u0644\u0627\u0645\u0627\u062A.'
    },
    checksList: [
      { name: { en: 'Reflected XSS Detection', ar: '\u0643\u0634\u0641 XSS \u0627\u0644\u0645\u0646\u0639\u0643\u0633' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 6.1 },
      { name: { en: 'DOM-Based XSS Indicators', ar: '\u0645\u0624\u0634\u0631\u0627\u062A XSS \u0627\u0644\u0645\u0628\u0646\u064A \u0639\u0644\u0649 DOM' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 0 },
      { name: { en: 'Input Sanitization Check', ar: '\u0641\u062D\u0635 \u062A\u0639\u0642\u064A\u0645 \u0627\u0644\u0645\u062F\u062E\u0644\u0627\u062A' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 0 },
      { name: { en: 'Content-Type & XSS Headers', ar: '\u0631\u0624\u0648\u0633 Content-Type \u0648XSS' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 0 },
      { name: { en: 'URL Parameter Reflection', ar: '\u0627\u0646\u0639\u0643\u0627\u0633 \u0645\u0639\u0627\u0645\u0644\u0627\u062A URL' }, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 0 },
    ]
  },
  {
    id: 'secrets', icon: '\u{1F511}',
    name: { en: 'Secrets Detection', ar: '\u0643\u0634\u0641 \u0627\u0644\u0623\u0633\u0631\u0627\u0631' },
    category: 'secrets', weight: 8, checks: 4,
    plans: ['basic', 'pro', 'enterprise'],
    desc: {
      en: 'Scans for exposed API keys, private keys, database connection strings, and passwords.',
      ar: '\u0641\u062D\u0635 \u0645\u0641\u0627\u062A\u064A\u062D API \u0627\u0644\u0645\u0643\u0634\u0648\u0641\u0629\u060C \u0627\u0644\u0645\u0641\u0627\u062A\u064A\u062D \u0627\u0644\u062E\u0627\u0635\u0629\u060C \u0633\u0644\u0627\u0633\u0644 \u0627\u062A\u0635\u0627\u0644 \u0642\u0648\u0627\u0639\u062F \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A\u060C \u0648\u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631.'
    },
    checksList: [
      { name: { en: 'API Key Exposure', ar: '\u0643\u0634\u0641 \u0645\u0641\u0627\u062A\u064A\u062D API' }, owasp: 'A05:2021', cwe: 'CWE-798', cvss: 9.8 },
      { name: { en: 'Private Key Exposure', ar: '\u0643\u0634\u0641 \u0627\u0644\u0645\u0641\u0627\u062A\u064A\u062D \u0627\u0644\u062E\u0627\u0635\u0629' }, owasp: 'A05:2021', cwe: 'CWE-312', cvss: 9.8 },
      { name: { en: 'Database Connection Strings', ar: '\u0633\u0644\u0627\u0633\u0644 \u0627\u062A\u0635\u0627\u0644 \u0642\u0648\u0627\u0639\u062F \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 9.8 },
      { name: { en: 'Email/Password Exposure', ar: '\u0643\u0634\u0641 \u0627\u0644\u0628\u0631\u064A\u062F/\u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631' }, owasp: 'A05:2021', cwe: 'CWE-312', cvss: 0 },
    ]
  },
  {
    id: 'subdomains', icon: '\u{1F30D}',
    name: { en: 'Subdomain Discovery', ar: '\u0627\u0643\u062A\u0634\u0627\u0641 \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629' },
    category: 'subdomains', weight: 5, checks: 3,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Enumerates subdomains and checks for HTTPS coverage and subdomain takeover risks.',
      ar: '\u062A\u0639\u062F\u0627\u062F \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629 \u0648\u0641\u062D\u0635 \u062A\u063A\u0637\u064A\u0629 HTTPS \u0648\u0645\u062E\u0627\u0637\u0631 \u0627\u0644\u0627\u0633\u062A\u064A\u0644\u0627\u0621.'
    },
    checksList: [
      { name: { en: 'Common Subdomain Enumeration', ar: '\u062A\u0639\u062F\u0627\u062F \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629 \u0627\u0644\u0634\u0627\u0626\u0639\u0629' }, owasp: 'A05:2021', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'Subdomain Security Check', ar: '\u0641\u062D\u0635 \u0623\u0645\u0627\u0646 \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629' }, owasp: 'A05:2021', cwe: 'CWE-16', cvss: 0 },
      { name: { en: 'Subdomain Takeover Risk', ar: '\u0645\u062E\u0627\u0637\u0631 \u0627\u0633\u062A\u064A\u0644\u0627\u0621 \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0641\u0631\u0639\u064A\u0629' }, owasp: 'A05:2021', cwe: 'CWE-16', cvss: 8.6 },
    ]
  },
  {
    id: 'tech_stack', icon: '\u{1F527}',
    name: { en: 'Technology Detection', ar: '\u0643\u0634\u0641 \u0627\u0644\u062A\u0642\u0646\u064A\u0627\u062A' },
    category: 'tech_stack', weight: 4, checks: 3,
    plans: ['pro', 'enterprise'],
    desc: {
      en: 'Identifies web frameworks, server technologies, and JavaScript libraries in use.',
      ar: '\u062A\u062D\u062F\u064A\u062F \u0623\u0637\u0631 \u0627\u0644\u0648\u064A\u0628\u060C \u062A\u0642\u0646\u064A\u0627\u062A \u0627\u0644\u062E\u0627\u062F\u0645\u060C \u0648\u0645\u0643\u062A\u0628\u0627\u062A JavaScript \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645\u0629.'
    },
    checksList: [
      { name: { en: 'Web Framework Detection', ar: '\u0643\u0634\u0641 \u0625\u0637\u0627\u0631 \u0627\u0644\u0648\u064A\u0628' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'Server Technology Detection', ar: '\u0643\u0634\u0641 \u062A\u0642\u0646\u064A\u0629 \u0627\u0644\u062E\u0627\u062F\u0645' }, owasp: 'Info', cwe: '-', cvss: 0 },
      { name: { en: 'JavaScript Library Inventory', ar: '\u062C\u0631\u062F \u0645\u0643\u062A\u0628\u0627\u062A JavaScript' }, owasp: 'Info', cwe: '-', cvss: 0 },
    ]
  },
  {
    name: { en: 'Backup & Sensitive Files', ar: 'Backup Files' },
    category: 'backup_files', weight: 12, checks: 60,
    plans: ['basic', 'pro', 'business', 'enterprise'],
    desc: {
      en: 'Deep enumeration of 60+ sensitive file paths: SQL dumps, config backups, archives, IDE files, log files, git/svn metadata, .env variants, phpMyAdmin, and server-status endpoints.',
      ar: 'Deep enumeration of 60+ sensitive file paths.'
    },
    checksList: [
      { name: { en: 'SQL Dump Exposed', ar: 'SQL Dump Exposed' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 9.8 },
      { name: { en: 'Config Backup Leaked', ar: 'Config Backup' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 9.8 },
      { name: { en: 'Site Archive Exposed', ar: 'Site Archive' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 8.6 },
      { name: { en: 'Environment File Variants', ar: 'Environment Files' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 9.8 },
      { name: { en: 'Git/SVN Repository Exposure', ar: 'Git/SVN Repository' }, owasp: 'A05:2021', cwe: 'CWE-538', cvss: 9.8 },
      { name: { en: 'phpMyAdmin / Adminer Exposed', ar: 'phpMyAdmin' }, owasp: 'A07:2021', cwe: 'CWE-284', cvss: 7.5 },
      { name: { en: 'Server Status / Info Pages', ar: 'Server Status' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 7.5 },
    ]
  },
  {
    name: { en: 'CMS CVE Matching', ar: 'CMS CVE Matching' },
    category: 'cms_cve', weight: 14, checks: 25,
    plans: ['basic', 'pro', 'business', 'enterprise'],
    desc: {
      en: 'Detects CMS (WordPress, Joomla, Drupal, Moodle, phpBB) and version, then matches against curated database of 25+ critical CVEs.',
      ar: 'Detects CMS and version, matches 25+ CVEs.'
    },
    checksList: [
      { name: { en: 'CMS Type Detection', ar: 'CMS Type Detection' }, owasp: 'A06:2021', cwe: 'CWE-1395', cvss: 0 },
      { name: { en: 'CMS Version Fingerprinting', ar: 'CMS Version Fingerprinting' }, owasp: 'A06:2021', cwe: 'CWE-1395', cvss: 5.3 },
      { name: { en: 'Known CVE Matching', ar: 'Known CVE Matching' }, owasp: 'A06:2021', cwe: 'CWE-1395', cvss: 9.8 },
    ]
  },
  {
    name: { en: 'JavaScript Secrets', ar: 'JavaScript Secrets' },
    category: 'js_secrets', weight: 12, checks: 23,
    plans: ['basic', 'pro', 'business', 'enterprise'],
    desc: {
      en: 'Fetches external JavaScript files and scans for 23 types of leaked secrets: AWS, Google, Stripe, GitHub tokens, webhooks, JWT, RSA keys.',
      ar: 'Scans external JavaScript files for 23 types of leaked secrets.'
    },
    checksList: [
      { name: { en: 'AWS Access Keys Leaked', ar: 'AWS Keys Leaked' }, owasp: 'A07:2021', cwe: 'CWE-798', cvss: 9.8 },
      { name: { en: 'Google API Keys Leaked', ar: 'Google API Keys' }, owasp: 'A07:2021', cwe: 'CWE-798', cvss: 7.5 },
      { name: { en: 'Stripe / Payment Keys Leaked', ar: 'Stripe Keys' }, owasp: 'A07:2021', cwe: 'CWE-798', cvss: 9.8 },
      { name: { en: 'GitHub / GitLab Tokens Leaked', ar: 'GitHub Tokens' }, owasp: 'A07:2021', cwe: 'CWE-798', cvss: 9.8 },
      { name: { en: 'Webhooks Leaked', ar: 'Webhooks Leaked' }, owasp: 'A07:2021', cwe: 'CWE-798', cvss: 7.5 },
      { name: { en: 'JWT / RSA Private Keys Leaked', ar: 'JWT / RSA Keys' }, owasp: 'A07:2021', cwe: 'CWE-798', cvss: 9.8 },
    ]
  },
  {
    name: { en: 'WordPress Deep Security', ar: 'WordPress Deep Security' },
    category: 'wp_deep', weight: 18, checks: 7,
    plans: ['basic', 'pro', 'business', 'enterprise'],
    desc: {
      en: 'Covers 80% of real-world WordPress attack vectors: plugin/theme enumeration with 25+ known CVEs, user enumeration detection, default admin username check, security plugin presence, wp-cron DoS abuse test.',
      ar: 'Covers 80% of WordPress attack vectors.'
    },
    checksList: [
      { name: { en: 'Plugin Enumeration + CVE Matching', ar: 'Plugin CVE Matching' }, owasp: 'A06:2021', cwe: 'CWE-1395', cvss: 9.9 },
      { name: { en: 'Theme Enumeration + CVE Matching', ar: 'Theme CVE Matching' }, owasp: 'A06:2021', cwe: 'CWE-1395', cvss: 9.8 },
      { name: { en: 'User Enumeration (/?author=N)', ar: 'User Enumeration' }, owasp: 'A01:2021', cwe: 'CWE-200', cvss: 7.5 },
      { name: { en: 'Default Admin Username Detection', ar: 'Default Admin Username' }, owasp: 'A07:2021', cwe: 'CWE-521', cvss: 7.5 },
      { name: { en: 'Security Plugin Presence', ar: 'Security Plugin' }, owasp: 'A05:2021', cwe: 'CWE-1188', cvss: 5.3 },
      { name: { en: 'wp-cron.php DoS Amplification', ar: 'wp-cron DoS' }, owasp: 'A05:2021', cwe: 'CWE-400', cvss: 5.3 },
      { name: { en: 'License/Install File Leaks', ar: 'License File Leaks' }, owasp: 'A05:2021', cwe: 'CWE-200', cvss: 3.7 },
    ]
  },
]

const faqItems = [
  {
    q: { en: 'How is the score calculated?', ar: '\u0643\u064A\u0641 \u064A\u062A\u0645 \u062D\u0633\u0627\u0628 \u0627\u0644\u062F\u0631\u062C\u0629\u061F' },
    a: {
      en: 'Each check is scored on a 0-1000 scale. The overall score is a weighted average: Overall Score = SUM(check_score x check_weight) / SUM(check_weight). Each scanner and its individual checks have assigned weights reflecting their security importance.',
      ar: '\u064A\u062A\u0645 \u062A\u0642\u064A\u064A\u0645 \u0643\u0644 \u0641\u062D\u0635 \u0639\u0644\u0649 \u0645\u0642\u064A\u0627\u0633 0-1000. \u0627\u0644\u062F\u0631\u062C\u0629 \u0627\u0644\u0625\u062C\u0645\u0627\u0644\u064A\u0629 \u0647\u064A \u0645\u062A\u0648\u0633\u0637 \u0645\u0631\u062C\u062D: \u0627\u0644\u062F\u0631\u062C\u0629 = \u0645\u062C\u0645\u0648\u0639(\u062F\u0631\u062C\u0629_\u0627\u0644\u0641\u062D\u0635 x \u0648\u0632\u0646_\u0627\u0644\u0641\u062D\u0635) / \u0645\u062C\u0645\u0648\u0639(\u0627\u0644\u0623\u0648\u0632\u0627\u0646). \u0644\u0643\u0644 \u0641\u0627\u062D\u0635 \u0648\u0641\u062D\u0648\u0635\u0627\u062A\u0647 \u0623\u0648\u0632\u0627\u0646 \u062A\u0639\u0643\u0633 \u0623\u0647\u0645\u064A\u062A\u0647\u0627 \u0627\u0644\u0623\u0645\u0646\u064A\u0629.'
    }
  },
  {
    q: { en: 'What does each grade mean?', ar: '\u0645\u0627\u0630\u0627 \u064A\u0639\u0646\u064A \u0643\u0644 \u062A\u0642\u062F\u064A\u0631\u061F' },
    a: {
      en: 'A+ (900-1000): Excellent, follows best practices. A (750-899): Good, minor improvements possible. B (500-749): Fair, notable issues to address. C (200-499): Poor, significant problems. F (0-199): Critical, immediate attention required.',
      ar: 'A+ (900-1000): \u0645\u0645\u062A\u0627\u0632\u060C \u064A\u062A\u0628\u0639 \u0623\u0641\u0636\u0644 \u0627\u0644\u0645\u0645\u0627\u0631\u0633\u0627\u062A. A (750-899): \u062C\u064A\u062F \u062C\u062F\u0627\u064B\u060C \u062A\u062D\u0633\u064A\u0646\u0627\u062A \u0637\u0641\u064A\u0641\u0629 \u0645\u0645\u0643\u0646\u0629. B (500-749): \u0645\u062A\u0648\u0633\u0637\u060C \u0645\u0634\u0627\u0643\u0644 \u0645\u0644\u062D\u0648\u0638\u0629. C (200-499): \u0636\u0639\u064A\u0641\u060C \u0645\u0634\u0627\u0643\u0644 \u0643\u0628\u064A\u0631\u0629. F (0-199): \u062D\u0631\u062C\u060C \u064A\u062A\u0637\u0644\u0628 \u0627\u0647\u062A\u0645\u0627\u0645\u0627\u064B \u0641\u0648\u0631\u064A\u0627\u064B.'
    }
  },
  {
    q: { en: 'How to improve my score?', ar: '\u0643\u064A\u0641 \u0623\u062D\u0633\u0651\u0646 \u062F\u0631\u062C\u062A\u064A\u061F' },
    a: {
      en: 'Start with the highest-weight categories: 1) Enable HTTPS with a valid certificate and TLS 1.2+. 2) Add all security headers (HSTS, CSP, X-Frame-Options). 3) Use a CDN with WAF (e.g., Cloudflare). 4) Secure cookies with Secure, HttpOnly, SameSite. 5) Remove exposed sensitive files. Use the AI Analysis feature for personalized recommendations.',
      ar: '\u0627\u0628\u062F\u0623 \u0628\u0627\u0644\u0641\u0626\u0627\u062A \u0627\u0644\u0623\u0639\u0644\u0649 \u0648\u0632\u0646\u0627\u064B: 1) \u0641\u0639\u0651\u0644 HTTPS \u0628\u0634\u0647\u0627\u062F\u0629 \u0635\u0627\u0644\u062D\u0629 \u0648TLS 1.2+. 2) \u0623\u0636\u0641 \u062C\u0645\u064A\u0639 \u0631\u0624\u0648\u0633 \u0627\u0644\u0623\u0645\u0627\u0646 (HSTS\u060C CSP\u060C X-Frame-Options). 3) \u0627\u0633\u062A\u062E\u062F\u0645 CDN \u0645\u0639 WAF (\u0645\u062B\u0644 Cloudflare). 4) \u0623\u0645\u0651\u0646 \u0627\u0644\u0643\u0648\u0643\u064A\u0632 \u0628\u0640 Secure\u060C HttpOnly\u060C SameSite. 5) \u0623\u0632\u0644 \u0627\u0644\u0645\u0644\u0641\u0627\u062A \u0627\u0644\u062D\u0633\u0627\u0633\u0629 \u0627\u0644\u0645\u0643\u0634\u0648\u0641\u0629. \u0627\u0633\u062A\u062E\u062F\u0645 \u0645\u064A\u0632\u0629 \u062A\u062D\u0644\u064A\u0644 AI \u0644\u0644\u062A\u0648\u0635\u064A\u0627\u062A \u0627\u0644\u0645\u062E\u0635\u0635\u0629.'
    }
  },
  {
    q: { en: 'How often should I scan?', ar: '\u0643\u0645 \u0645\u0631\u0629 \u064A\u062C\u0628 \u0623\u0646 \u0623\u0641\u062D\u0635\u061F' },
    a: {
      en: 'We recommend: Weekly scans for production websites, after any server configuration change, after deploying updates or new features, and monthly for low-traffic sites. Use scheduled scans to automate this.',
      ar: '\u0646\u0648\u0635\u064A \u0628\u0640: \u0641\u062D\u0635 \u0623\u0633\u0628\u0648\u0639\u064A \u0644\u0644\u0645\u0648\u0627\u0642\u0639 \u0627\u0644\u0625\u0646\u062A\u0627\u062C\u064A\u0629\u060C \u0628\u0639\u062F \u0623\u064A \u062A\u063A\u064A\u064A\u0631 \u0641\u064A \u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0644\u062E\u0627\u062F\u0645\u060C \u0628\u0639\u062F \u0646\u0634\u0631 \u0627\u0644\u062A\u062D\u062F\u064A\u062B\u0627\u062A\u060C \u0648\u0634\u0647\u0631\u064A\u0627\u064B \u0644\u0644\u0645\u0648\u0627\u0642\u0639 \u0645\u0646\u062E\u0641\u0636\u0629 \u0627\u0644\u0632\u064A\u0627\u0631\u0627\u062A. \u0627\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0627\u0644\u0645\u062C\u062F\u0648\u0644\u0629 \u0644\u0623\u062A\u0645\u062A\u0629 \u0647\u0630\u0627.'
    }
  },
  {
    q: { en: 'Is the scan safe for my website?', ar: '\u0647\u0644 \u0627\u0644\u0641\u062D\u0635 \u0622\u0645\u0646 \u0644\u0645\u0648\u0642\u0639\u064A\u061F' },
    a: {
      en: 'Yes, absolutely. Seku uses only safe, non-destructive techniques. We never inject malicious payloads, modify data, or attempt exploitation. Our XSS scanner uses harmless canary strings, not actual attack payloads. The scan is equivalent to visiting your website with a browser.',
      ar: '\u0646\u0639\u0645\u060C \u0628\u0627\u0644\u062A\u0623\u0643\u064A\u062F. \u064A\u0633\u062A\u062E\u062F\u0645 Seku \u062A\u0642\u0646\u064A\u0627\u062A \u0622\u0645\u0646\u0629 \u0648\u063A\u064A\u0631 \u0645\u062F\u0645\u0631\u0629 \u0641\u0642\u0637. \u0644\u0627 \u0646\u062D\u0642\u0646 \u062D\u0645\u0648\u0644\u0627\u062A \u062E\u0628\u064A\u062B\u0629 \u0623\u0628\u062F\u0627\u064B\u060C \u0648\u0644\u0627 \u0646\u0639\u062F\u0651\u0644 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A\u060C \u0648\u0644\u0627 \u0646\u062D\u0627\u0648\u0644 \u0627\u0644\u0627\u0633\u062A\u063A\u0644\u0627\u0644. \u064A\u0633\u062A\u062E\u062F\u0645 \u0641\u0627\u062D\u0635 XSS \u0639\u0644\u0627\u0645\u0627\u062A \u063A\u064A\u0631 \u0636\u0627\u0631\u0629\u060C \u0648\u0644\u064A\u0633 \u062D\u0645\u0648\u0644\u0627\u062A \u0647\u062C\u0648\u0645 \u0641\u0639\u0644\u064A\u0629.'
    }
  },
  {
    q: { en: 'What is domain verification?', ar: '\u0645\u0627 \u0647\u0648 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642\u061F' },
    a: {
      en: 'Domain verification proves you own or control the website you want to scan. Add a TXT record with a unique code to your DNS settings. This prevents unauthorized scanning of websites you do not own. Admin users can skip this step.',
      ar: '\u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 \u064A\u062B\u0628\u062A \u0623\u0646\u0643 \u062A\u0645\u0644\u0643 \u0623\u0648 \u062A\u062A\u062D\u0643\u0645 \u0641\u064A \u0627\u0644\u0645\u0648\u0642\u0639 \u0627\u0644\u0630\u064A \u062A\u0631\u064A\u062F \u0641\u062D\u0635\u0647. \u0623\u0636\u0641 \u0633\u062C\u0644 TXT \u0628\u0631\u0645\u0632 \u0641\u0631\u064A\u062F \u0625\u0644\u0649 \u0625\u0639\u062F\u0627\u062F\u0627\u062A DNS \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0643. \u0647\u0630\u0627 \u064A\u0645\u0646\u0639 \u0627\u0644\u0641\u062D\u0635 \u063A\u064A\u0631 \u0627\u0644\u0645\u0635\u0631\u062D \u0628\u0647 \u0644\u0644\u0645\u0648\u0627\u0642\u0639 \u0627\u0644\u062A\u064A \u0644\u0627 \u062A\u0645\u0644\u0643\u0647\u0627.'
    }
  },
  {
    q: { en: 'How to export results?', ar: '\u0643\u064A\u0641 \u0623\u0635\u062F\u0651\u0631 \u0627\u0644\u0646\u062A\u0627\u0626\u062C\u061F' },
    a: {
      en: 'Seku supports multiple export formats: PDF Report (comprehensive with charts), CSV (for Excel/spreadsheet analysis), SARIF (for GitHub/VS Code integration). Go to any scan result page and click the Download button to choose your format.',
      ar: '\u064A\u062F\u0639\u0645 Seku \u0639\u062F\u0629 \u0635\u064A\u063A \u062A\u0635\u062F\u064A\u0631: \u062A\u0642\u0631\u064A\u0631 PDF (\u0634\u0627\u0645\u0644 \u0645\u0639 \u0631\u0633\u0648\u0645 \u0628\u064A\u0627\u0646\u064A\u0629)\u060C CSV (\u0644\u062A\u062D\u0644\u064A\u0644 Excel)\u060C SARIF (\u0644\u062A\u0643\u0627\u0645\u0644 GitHub/VS Code). \u0627\u0630\u0647\u0628 \u0625\u0644\u0649 \u0623\u064A \u0635\u0641\u062D\u0629 \u0646\u062A\u0627\u0626\u062C \u0641\u062D\u0635 \u0648\u0627\u0636\u063A\u0637 \u0632\u0631 \u0627\u0644\u062A\u062D\u0645\u064A\u0644 \u0644\u0627\u062E\u062A\u064A\u0627\u0631 \u0627\u0644\u0635\u064A\u063A\u0629.'
    }
  },
  {
    q: { en: 'How does AI analysis work?', ar: '\u0643\u064A\u0641 \u064A\u0639\u0645\u0644 \u062A\u062D\u0644\u064A\u0644 AI\u061F' },
    a: {
      en: 'AI Analysis uses your configured LLM provider (DeepSeek, OpenAI, Anthropic, etc.) to analyze scan results. It provides: an executive summary, detailed fix instructions for each vulnerability, a step-by-step roadmap to achieve a perfect score, and code examples. Configure your AI provider in Settings.',
      ar: '\u064A\u0633\u062A\u062E\u062F\u0645 \u062A\u062D\u0644\u064A\u0644 AI \u0645\u0632\u0648\u062F LLM \u0627\u0644\u0645\u0647\u064A\u0623 (\u0645\u062B\u0644 DeepSeek\u060C OpenAI\u060C Anthropic) \u0644\u062A\u062D\u0644\u064A\u0644 \u0646\u062A\u0627\u0626\u062C \u0627\u0644\u0641\u062D\u0635. \u064A\u0642\u062F\u0645: \u0645\u0644\u062E\u0635 \u062A\u0646\u0641\u064A\u0630\u064A\u060C \u062A\u0639\u0644\u064A\u0645\u0627\u062A \u0625\u0635\u0644\u0627\u062D \u0645\u0641\u0635\u0644\u0629 \u0644\u0643\u0644 \u062B\u063A\u0631\u0629\u060C \u062E\u0627\u0631\u0637\u0629 \u0637\u0631\u064A\u0642 \u0644\u0644\u0648\u0635\u0648\u0644 \u0644\u0644\u062F\u0631\u062C\u0629 \u0627\u0644\u0643\u0627\u0645\u0644\u0629\u060C \u0648\u0623\u0645\u062B\u0644\u0629 \u0628\u0631\u0645\u062C\u064A\u0629. \u0647\u064A\u0651\u0626 \u0645\u0632\u0648\u062F AI \u0641\u064A \u0627\u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A.'
    }
  },
  {
    q: { en: 'What plans are available?', ar: '\u0645\u0627 \u0627\u0644\u062E\u0637\u0637 \u0627\u0644\u0645\u062A\u0627\u062D\u0629\u061F' },
    a: {
      en: 'Free: 5 websites, 10 scans/month, 5 scanner categories. Basic: 20 websites, 50 scans/month, 13 categories. Pro: 100 websites, 200 scans/month, 22 categories. Enterprise: Unlimited websites, unlimited scans, all 25 categories plus priority support.',
      ar: '\u0645\u062C\u0627\u0646\u064A: 5 \u0645\u0648\u0627\u0642\u0639\u060C 10 \u0641\u062D\u0648\u0635\u0627\u062A/\u0634\u0647\u0631\u060C 5 \u0641\u0626\u0627\u062A. \u0623\u0633\u0627\u0633\u064A: 20 \u0645\u0648\u0642\u0639\u060C 50 \u0641\u062D\u0635/\u0634\u0647\u0631\u060C 13 \u0641\u0626\u0629. \u0627\u062D\u062A\u0631\u0627\u0641\u064A: 100 \u0645\u0648\u0642\u0639\u060C 200 \u0641\u062D\u0635/\u0634\u0647\u0631\u060C 22 \u0641\u0626\u0629. \u0645\u0624\u0633\u0633\u0627\u062A: \u0645\u0648\u0627\u0642\u0639 \u063A\u064A\u0631 \u0645\u062D\u062F\u0648\u062F\u0629\u060C \u0641\u062D\u0648\u0635\u0627\u062A \u063A\u064A\u0631 \u0645\u062D\u062F\u0648\u062F\u0629\u060C \u062C\u0645\u064A\u0639 \u0627\u0644\u0640 25 \u0641\u0626\u0629 \u0645\u0639 \u062F\u0639\u0645 \u0623\u0648\u0644\u0648\u064A.'
    }
  },
  {
    q: { en: 'How to set up scheduled scans?', ar: '\u0643\u064A\u0641 \u0623\u0639\u062F\u0651 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0627\u0644\u0645\u062C\u062F\u0648\u0644\u0629\u061F' },
    a: {
      en: 'Go to Schedules page, click "Add Schedule", select frequency (daily/weekly/monthly), choose the hour (UTC), and select target websites. The system will automatically run scans at the specified time and send notifications via your configured webhooks.',
      ar: '\u0627\u0630\u0647\u0628 \u0625\u0644\u0649 \u0635\u0641\u062D\u0629 \u0627\u0644\u062C\u062F\u0648\u0644\u0629\u060C \u0627\u0636\u063A\u0637 "\u0625\u0636\u0627\u0641\u0629 \u062C\u062F\u0648\u0644\u0629"\u060C \u0627\u062E\u062A\u0631 \u0627\u0644\u062A\u0643\u0631\u0627\u0631 (\u064A\u0648\u0645\u064A/\u0623\u0633\u0628\u0648\u0639\u064A/\u0634\u0647\u0631\u064A)\u060C \u0627\u062E\u062A\u0631 \u0627\u0644\u0633\u0627\u0639\u0629 (UTC)\u060C \u0648\u062D\u062F\u062F \u0627\u0644\u0645\u0648\u0627\u0642\u0639 \u0627\u0644\u0645\u0633\u062A\u0647\u062F\u0641\u0629. \u0633\u064A\u0634\u063A\u0651\u0644 \u0627\u0644\u0646\u0638\u0627\u0645 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0641\u064A \u0627\u0644\u0648\u0642\u062A \u0627\u0644\u0645\u062D\u062F\u062F \u0648\u064A\u0631\u0633\u0644 \u0625\u0634\u0639\u0627\u0631\u0627\u062A \u0639\u0628\u0631 \u0627\u0644\u0648\u064A\u0628\u0647\u0648\u0643 \u0627\u0644\u0645\u0647\u064A\u0623\u0629.'
    }
  },
]

const grades = [
  { grade: 'A+', range: '950-1000', color: 'bg-emerald-500', textColor: 'text-white', meaning: { en: 'Excellent', ar: '\u0645\u0645\u062A\u0627\u0632' } },
  { grade: 'A', range: '900-949', color: 'bg-emerald-400', textColor: 'text-white', meaning: { en: 'Very Good', ar: '\u062C\u064A\u062F \u062C\u062F\u0627\u064B' } },
  { grade: 'B+', range: '800-899', color: 'bg-green-400', textColor: 'text-white', meaning: { en: 'Good', ar: '\u062C\u064A\u062F' } },
  { grade: 'B', range: '750-799', color: 'bg-lime-500', textColor: 'text-white', meaning: { en: 'Above Average', ar: '\u0641\u0648\u0642 \u0627\u0644\u0645\u062A\u0648\u0633\u0637' } },
  { grade: 'C', range: '500-749', color: 'bg-yellow-500', textColor: 'text-white', meaning: { en: 'Average', ar: '\u0645\u062A\u0648\u0633\u0637' } },
  { grade: 'D', range: '200-499', color: 'bg-orange-500', textColor: 'text-white', meaning: { en: 'Below Average', ar: '\u062F\u0648\u0646 \u0627\u0644\u0645\u062A\u0648\u0633\u0637' } },
  { grade: 'F', range: '0-199', color: 'bg-red-500', textColor: 'text-white', meaning: { en: 'Critical', ar: '\u062D\u0631\u062C' } },
]

const apiEndpoints = [
  { method: 'POST', path: '/api/auth/login', desc: { en: 'Authenticate and get JWT token', ar: '\u0627\u0644\u0645\u0635\u0627\u062F\u0642\u0629 \u0648\u0627\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u0631\u0645\u0632 JWT' } },
  { method: 'POST', path: '/api/auth/register', desc: { en: 'Register a new account', ar: '\u062A\u0633\u062C\u064A\u0644 \u062D\u0633\u0627\u0628 \u062C\u062F\u064A\u062F' } },
  { method: 'GET', path: '/api/targets', desc: { en: 'List all targets', ar: '\u0639\u0631\u0636 \u062C\u0645\u064A\u0639 \u0627\u0644\u0645\u0648\u0627\u0642\u0639' } },
  { method: 'POST', path: '/api/targets', desc: { en: 'Add a new target', ar: '\u0625\u0636\u0627\u0641\u0629 \u0645\u0648\u0642\u0639 \u062C\u062F\u064A\u062F' } },
  { method: 'DELETE', path: '/api/targets/:id', desc: { en: 'Delete a target', ar: '\u062D\u0630\u0641 \u0645\u0648\u0642\u0639' } },
  { method: 'POST', path: '/api/targets/:id/verify', desc: { en: 'Verify domain ownership', ar: '\u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0645\u0644\u0643\u064A\u0629 \u0627\u0644\u0646\u0637\u0627\u0642' } },
  { method: 'POST', path: '/api/scans', desc: { en: 'Start a new scan', ar: '\u0628\u062F\u0621 \u0641\u062D\u0635 \u062C\u062F\u064A\u062F' } },
  { method: 'GET', path: '/api/scans', desc: { en: 'List all scans', ar: '\u0639\u0631\u0636 \u062C\u0645\u064A\u0639 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A' } },
  { method: 'GET', path: '/api/scans/:id', desc: { en: 'Get scan details', ar: '\u0639\u0631\u0636 \u062A\u0641\u0627\u0635\u064A\u0644 \u0627\u0644\u0641\u062D\u0635' } },
  { method: 'GET', path: '/api/results/:id', desc: { en: 'Get scan result details', ar: '\u0639\u0631\u0636 \u062A\u0641\u0627\u0635\u064A\u0644 \u0627\u0644\u0646\u062A\u064A\u062C\u0629' } },
  { method: 'GET', path: '/api/results/:id/pdf', desc: { en: 'Download PDF report', ar: '\u062A\u062D\u0645\u064A\u0644 \u062A\u0642\u0631\u064A\u0631 PDF' } },
  { method: 'POST', path: '/api/results/:id/ai-analysis', desc: { en: 'Run AI analysis on result', ar: '\u062A\u0634\u063A\u064A\u0644 \u062A\u062D\u0644\u064A\u0644 AI \u0639\u0644\u0649 \u0627\u0644\u0646\u062A\u064A\u062C\u0629' } },
  { method: 'GET', path: '/api/leaderboard', desc: { en: 'Get leaderboard rankings', ar: '\u0639\u0631\u0636 \u062A\u0631\u062A\u064A\u0628 \u0627\u0644\u0645\u0648\u0627\u0642\u0639' } },
  { method: 'POST', path: '/api/api-keys', desc: { en: 'Generate API key', ar: '\u062A\u0648\u0644\u064A\u062F \u0645\u0641\u062A\u0627\u062D API' } },
  { method: 'GET', path: '/api/schedules', desc: { en: 'List scan schedules', ar: '\u0639\u0631\u0636 \u0627\u0644\u062C\u062F\u0627\u0648\u0644' } },
  { method: 'POST', path: '/api/schedules', desc: { en: 'Create a schedule', ar: '\u0625\u0646\u0634\u0627\u0621 \u062C\u062F\u0648\u0644\u0629' } },
]

const filteredScanners = computed(() => {
  if (!searchQuery.value) return scanners
  const q = searchQuery.value.toLowerCase()
  return scanners.filter(s =>
    s.name.en.toLowerCase().includes(q) ||
    s.name.ar.includes(q) ||
    s.category.includes(q) ||
    s.desc.en.toLowerCase().includes(q) ||
    s.desc.ar.includes(q)
  )
})

const filteredFaqs = computed(() => {
  if (!searchQuery.value) return faqItems
  const q = searchQuery.value.toLowerCase()
  return faqItems.filter(f =>
    f.q.en.toLowerCase().includes(q) ||
    f.q.ar.includes(q) ||
    f.a.en.toLowerCase().includes(q) ||
    f.a.ar.includes(q)
  )
})

function toggleScanner(id) {
  expandedScanner.value = expandedScanner.value === id ? null : id
}

function toggleFaq(index) {
  expandedFaq.value = expandedFaq.value === index ? null : index
}

function planBadgeColor(plan) {
  const colors = {
    free: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    basic: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    pro: 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300',
    enterprise: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
  }
  return colors[plan] || colors.free
}

function planLabel(plan) {
  const labels = {
    free: { en: 'Free', ar: '\u0645\u062C\u0627\u0646\u064A' },
    basic: { en: 'Basic', ar: '\u0623\u0633\u0627\u0633\u064A' },
    pro: { en: 'Pro', ar: '\u0627\u062D\u062A\u0631\u0627\u0641\u064A' },
    enterprise: { en: 'Enterprise', ar: '\u0645\u0624\u0633\u0633\u0627\u062A' },
  }
  return labels[plan]?.[lang.value] || plan
}

function methodColor(method) {
  const colors = {
    GET: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    POST: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    PUT: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    DELETE: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
  }
  return colors[method] || colors.GET
}

function copyText(text) {
  navigator.clipboard.writeText(text)
}

function printPage() {
  window.print()
}
</script>

<template>
  <div class="max-w-7xl mx-auto">
    <!-- Header -->
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
        {{ lang === 'ar' ? '\u0645\u0631\u0643\u0632 \u0627\u0644\u062A\u0648\u062B\u064A\u0642' : 'Documentation Center' }}
      </h1>
      <p class="mt-2 text-gray-600 dark:text-gray-400">
        {{ lang === 'ar' ? '\u0643\u0644 \u0645\u0627 \u062A\u062D\u062A\u0627\u062C \u0645\u0639\u0631\u0641\u062A\u0647 \u0639\u0646 Seku' : 'Everything you need to know about Seku' }}
      </p>
    </div>

    <!-- Search & Print Bar -->
    <div class="flex flex-col sm:flex-row gap-3 mb-6">
      <div class="relative flex-1">
        <svg class="absolute top-3 w-5 h-5 text-gray-400" :class="lang === 'ar' ? 'right-3' : 'left-3'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
        <input
          v-model="searchQuery"
          type="text"
          :placeholder="lang === 'ar' ? '\u0627\u0628\u062D\u062B \u0641\u064A \u0627\u0644\u062A\u0648\u062B\u064A\u0642...' : 'Search documentation...'"
          class="w-full py-2.5 border border-gray-300 dark:border-slate-600 rounded-xl bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-200 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
          :class="lang === 'ar' ? 'pr-10 pl-4' : 'pl-10 pr-4'"
        />
      </div>
      <button @click="printPage" class="flex items-center gap-2 px-4 py-2.5 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-slate-600 transition-colors">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/>
        </svg>
        {{ lang === 'ar' ? '\u0637\u0628\u0627\u0639\u0629 \u0627\u0644\u0635\u0641\u062D\u0629' : 'Print Page' }}
      </button>
    </div>

    <!-- Layout: sidebar + content -->
    <div class="flex flex-col lg:flex-row gap-6">
      <!-- Tab Navigation - Sidebar on desktop, horizontal on mobile -->
      <nav class="lg:w-64 flex-shrink-0">
        <div class="flex lg:flex-col gap-1 overflow-x-auto lg:overflow-visible pb-2 lg:pb-0 lg:sticky lg:top-4">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            @click="activeTab = tab.id"
            :class="[
              activeTab === tab.id
                ? 'bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 border-indigo-500'
                : 'bg-white dark:bg-slate-700 text-gray-700 dark:text-gray-300 border-transparent hover:bg-gray-50 dark:hover:bg-slate-600',
            ]"
            class="flex items-center gap-3 px-4 py-3 rounded-xl border-2 transition-all whitespace-nowrap text-sm font-medium min-w-fit"
          >
            <span class="text-lg">{{ tab.icon }}</span>
            <span>{{ tabNames[tab.id]?.[lang] || tab.id }}</span>
          </button>
        </div>
      </nav>

      <!-- Content Area -->
      <div class="flex-1 min-w-0">

        <!-- Getting Started -->
        <div v-if="activeTab === 'getting-started'" class="space-y-6">
          <div class="bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl p-8 text-white">
            <h2 class="text-2xl font-bold mb-2">
              {{ lang === 'ar' ? '\u0645\u0631\u062D\u0628\u0627\u064B \u0628\u0643 \u0641\u064A Seku' : 'Welcome to Seku' }}
            </h2>
            <p class="opacity-90">
              {{ lang === 'ar' ? '\u0627\u062A\u0628\u0639 \u0647\u0630\u0647 \u0627\u0644\u062E\u0637\u0648\u0627\u062A \u0627\u0644\u0623\u0631\u0628\u0639 \u0644\u0628\u062F\u0621 \u0641\u062D\u0635 \u0623\u0645\u0627\u0646 \u0645\u0648\u0642\u0639\u0643' : 'Follow these 4 steps to start scanning your website security' }}
            </p>
          </div>

          <!-- Steps -->
          <div v-for="(step, i) in gettingStartedSteps" :key="i" class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <div class="flex items-start gap-4">
              <div class="flex-shrink-0 w-12 h-12 rounded-xl bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center text-2xl">
                {{ step.icon }}
              </div>
              <div class="flex-1">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <span class="inline-flex items-center justify-center w-7 h-7 rounded-full bg-indigo-600 text-white text-sm font-bold">{{ step.num }}</span>
                  {{ step.title[lang] }}
                </h3>
                <p class="mt-2 text-gray-600 dark:text-gray-400 leading-relaxed">{{ step.desc[lang] }}</p>
              </div>
            </div>
          </div>

          <!-- Tip Box -->
          <div class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700 rounded-xl p-5">
            <div class="flex items-start gap-3">
              <span class="text-xl flex-shrink-0">\u{1F4A1}</span>
              <div>
                <h4 class="font-semibold text-amber-800 dark:text-amber-300">
                  {{ lang === 'ar' ? '\u0646\u0635\u064A\u062D\u0629' : 'Pro Tip' }}
                </h4>
                <p class="mt-1 text-amber-700 dark:text-amber-400 text-sm">
                  {{ lang === 'ar'
                    ? '\u0627\u0628\u062F\u0623 \u0628\u0627\u0644\u0641\u062D\u0635 \u0627\u0644\u062E\u0641\u064A\u0641 \u0644\u0644\u062D\u0635\u0648\u0644 \u0639\u0644\u0649 \u0646\u0638\u0631\u0629 \u0633\u0631\u064A\u0639\u0629\u060C \u062B\u0645 \u0627\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0641\u062D\u0635 \u0627\u0644\u0639\u0645\u064A\u0642 \u0644\u0644\u062A\u062F\u0642\u064A\u0642 \u0627\u0644\u0634\u0627\u0645\u0644. \u0641\u0639\u0651\u0644 \u0627\u0644\u0641\u062D\u0648\u0635\u0627\u062A \u0627\u0644\u0645\u062C\u062F\u0648\u0644\u0629 \u0644\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0627\u0644\u0645\u0633\u062A\u0645\u0631\u0629.'
                    : 'Start with a Light scan for a quick overview, then use Deep scan for comprehensive auditing. Enable scheduled scans for continuous monitoring.'
                  }}
                </p>
              </div>
            </div>
          </div>
        </div>

        <!-- Scanners -->
        <div v-if="activeTab === 'scanners'" class="space-y-4">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-xl font-bold text-gray-900 dark:text-white">
              {{ lang === 'ar' ? '25 \u0641\u0627\u062D\u0635 \u0623\u0645\u0646\u064A' : '25 Security Scanners' }}
            </h2>
            <span class="text-sm text-gray-500 dark:text-gray-400">
              {{ lang === 'ar' ? '\u0623\u0643\u062B\u0631 \u0645\u0646 100 \u0641\u062D\u0635 \u062A\u0641\u0635\u064A\u0644\u064A' : '100+ individual checks' }}
            </span>
          </div>

          <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <div
              v-for="scanner in filteredScanners"
              :key="scanner.id"
              class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 overflow-hidden transition-all hover:shadow-lg"
            >
              <button @click="toggleScanner(scanner.id)" class="w-full text-start p-5">
                <div class="flex items-start gap-3">
                  <span class="text-2xl">{{ scanner.icon }}</span>
                  <div class="flex-1 min-w-0">
                    <h3 class="font-semibold text-gray-900 dark:text-white text-sm">{{ scanner.name[lang] }}</h3>
                    <div class="flex items-center gap-2 mt-1 text-xs text-gray-500 dark:text-gray-400">
                      <span class="font-mono">{{ scanner.category }}</span>
                      <span>|</span>
                      <span>{{ lang === 'ar' ? '\u0648\u0632\u0646' : 'W' }}: {{ scanner.weight }}</span>
                      <span>|</span>
                      <span>{{ scanner.checks }} {{ lang === 'ar' ? '\u0641\u062D\u0635' : 'checks' }}</span>
                    </div>
                    <p class="mt-2 text-xs text-gray-600 dark:text-gray-400 line-clamp-2">{{ scanner.desc[lang] }}</p>
                    <div class="flex flex-wrap gap-1 mt-2">
                      <span v-for="plan in scanner.plans" :key="plan" :class="planBadgeColor(plan)" class="px-2 py-0.5 rounded-full text-xs font-medium">
                        {{ planLabel(plan) }}
                      </span>
                    </div>
                  </div>
                  <svg :class="expandedScanner === scanner.id ? 'rotate-180' : ''" class="w-5 h-5 text-gray-400 transition-transform flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                  </svg>
                </div>
              </button>

              <div v-if="expandedScanner === scanner.id" class="border-t border-gray-200 dark:border-slate-600 px-5 pb-5">
                <table class="w-full mt-3 text-xs">
                  <thead>
                    <tr class="text-gray-500 dark:text-gray-400">
                      <th class="text-start pb-2 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0641\u062D\u0635' : 'Check' }}</th>
                      <th class="text-start pb-2 font-medium">OWASP</th>
                      <th class="text-start pb-2 font-medium">CWE</th>
                      <th class="text-start pb-2 font-medium">CVSS</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(check, ci) in scanner.checksList" :key="ci" class="border-t border-gray-100 dark:border-slate-600">
                      <td class="py-2 text-gray-900 dark:text-gray-200">{{ check.name[lang] }}</td>
                      <td class="py-2 text-gray-500 dark:text-gray-400 font-mono">{{ check.owasp }}</td>
                      <td class="py-2 text-gray-500 dark:text-gray-400 font-mono">{{ check.cwe }}</td>
                      <td class="py-2">
                        <span v-if="check.cvss > 0" :class="check.cvss >= 7 ? 'text-red-600 dark:text-red-400' : check.cvss >= 4 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'" class="font-semibold">
                          {{ check.cvss }}
                        </span>
                        <span v-else class="text-gray-400">-</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        <!-- Scoring System -->
        <div v-if="activeTab === 'scoring'" class="space-y-6">
          <!-- Score Scale -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h2 class="text-xl font-bold text-gray-900 dark:text-white mb-4">
              {{ lang === 'ar' ? '\u0645\u0642\u064A\u0627\u0633 \u0627\u0644\u062F\u0631\u062C\u0627\u062A 0-1000' : '0-1000 Score Scale' }}
            </h2>
            <div class="space-y-2">
              <div v-for="g in grades" :key="g.grade" class="flex items-center gap-3">
                <span :class="[g.color, g.textColor]" class="inline-flex items-center justify-center w-12 h-8 rounded-lg font-bold text-sm">{{ g.grade }}</span>
                <span class="text-sm text-gray-600 dark:text-gray-400 w-24 font-mono">{{ g.range }}</span>
                <span class="text-sm text-gray-900 dark:text-gray-200">{{ g.meaning[lang] }}</span>
              </div>
            </div>
          </div>

          <!-- Weighted Average -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-3">
              {{ lang === 'ar' ? '\u0643\u064A\u0641 \u064A\u064F\u062D\u0633\u0628 \u0627\u0644\u0645\u062A\u0648\u0633\u0637 \u0627\u0644\u0645\u0631\u062C\u062D' : 'How Weighted Average Works' }}
            </h3>
            <div class="bg-slate-900 rounded-lg p-4 font-mono text-sm text-green-400 mb-4 overflow-x-auto">
              <div>Overall Score = SUM(check_score x check_weight) / SUM(check_weight)</div>
            </div>
            <p class="text-sm text-gray-600 dark:text-gray-400">
              {{ lang === 'ar'
                ? '\u0644\u0643\u0644 \u0641\u0627\u062D\u0635 \u0648\u0632\u0646 \u064A\u0639\u0643\u0633 \u0623\u0647\u0645\u064A\u062A\u0647. \u0645\u062B\u0644\u0627\u064B SSL/TLS \u0648\u0631\u0624\u0648\u0633 \u0627\u0644\u0623\u0645\u0627\u0646 \u0644\u0647\u0645\u0627 \u0648\u0632\u0646 20 (\u0627\u0644\u0623\u0639\u0644\u0649)\u060C \u0628\u064A\u0646\u0645\u0627 \u0643\u0634\u0641 \u0627\u0644\u062A\u0642\u0646\u064A\u0627\u062A \u0644\u0647 \u0648\u0632\u0646 4 (\u0627\u0644\u0623\u0642\u0644). \u0647\u0630\u0627 \u064A\u0639\u0646\u064A \u0623\u0646 \u0625\u0635\u0644\u0627\u062D SSL \u064A\u0624\u062B\u0631 \u0639\u0644\u0649 \u062F\u0631\u062C\u062A\u0643 \u0623\u0643\u062B\u0631 \u0628\u0643\u062B\u064A\u0631.'
                : 'Each scanner has a weight reflecting its importance. For example, SSL/TLS and Security Headers both have weight 20 (highest), while Technology Detection has weight 4 (lowest). This means fixing SSL issues impacts your score much more.'
              }}
            </p>
          </div>

          <!-- Confidence Score -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-3">
              {{ lang === 'ar' ? '\u062F\u0631\u062C\u0629 \u0627\u0644\u062B\u0642\u0629' : 'Confidence Score' }}
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div v-for="c in confidenceLevels" :key="c.pct" class="text-center p-3 bg-gray-50 dark:bg-slate-600 rounded-lg">
                <div class="text-lg font-bold text-indigo-600 dark:text-indigo-400">{{ c.pct }}</div>
                <div class="text-xs text-gray-600 dark:text-gray-400 mt-1">{{ c.label[lang] }}</div>
              </div>
            </div>
          </div>

          <!-- CVSS -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-3">CVSS v3.1</h3>
            <p class="text-sm text-gray-600 dark:text-gray-400 mb-3">
              {{ lang === 'ar'
                ? '\u0646\u0638\u0627\u0645 \u062A\u0642\u064A\u064A\u0645 \u0627\u0644\u062B\u063A\u0631\u0627\u062A \u0627\u0644\u0634\u0627\u0626\u0639 (CVSS) \u0644\u062A\u0642\u064A\u064A\u0645 \u062E\u0637\u0648\u0631\u0629 \u0627\u0644\u062B\u063A\u0631\u0627\u062A \u0627\u0644\u0623\u0645\u0646\u064A\u0629 \u0639\u0644\u0649 \u0645\u0642\u064A\u0627\u0633 0-10.'
                : 'The Common Vulnerability Scoring System (CVSS) rates vulnerability severity on a 0-10 scale.'
              }}
            </p>
            <div class="flex flex-wrap gap-2">
              <span class="px-3 py-1 bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300 rounded-full text-xs font-medium">9.0-10.0 Critical</span>
              <span class="px-3 py-1 bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300 rounded-full text-xs font-medium">7.0-8.9 High</span>
              <span class="px-3 py-1 bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300 rounded-full text-xs font-medium">4.0-6.9 Medium</span>
              <span class="px-3 py-1 bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 rounded-full text-xs font-medium">0.1-3.9 Low</span>
            </div>
          </div>

          <!-- Scan Policies -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-4">
              {{ lang === 'ar' ? '\u0633\u064A\u0627\u0633\u0627\u062A \u0627\u0644\u0641\u062D\u0635' : 'Scan Policies' }}
            </h3>
            <div class="overflow-x-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr class="text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-slate-600">
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0633\u064A\u0627\u0633\u0629' : 'Policy' }}</th>
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0641\u0626\u0627\u062A' : 'Categories' }}</th>
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0645\u0647\u0644\u0629' : 'Timeout' }}</th>
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0648\u0635\u0641' : 'Description' }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="p in scanPoliciesData" :key="p.name.en" class="border-t border-gray-100 dark:border-slate-600">
                    <td class="py-3 font-semibold text-gray-900 dark:text-white">{{ p.name[lang] }}</td>
                    <td class="py-3 text-gray-600 dark:text-gray-400">{{ p.cats }}</td>
                    <td class="py-3 text-gray-600 dark:text-gray-400 font-mono">{{ p.timeout }}</td>
                    <td class="py-3 text-gray-600 dark:text-gray-400 text-xs">{{ p.desc[lang] }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Reports -->
        <div v-if="activeTab === 'reports'" class="space-y-4">
          <div v-for="report in reportsData" :key="report.title.en" class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <div class="flex items-start gap-4">
              <span class="text-3xl flex-shrink-0">{{ report.icon }}</span>
              <div>
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">{{ report.title[lang] }}</h3>
                <p class="mt-2 text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{{ report.desc[lang] }}</p>
                <p class="mt-2 text-sm text-indigo-600 dark:text-indigo-400 font-medium">{{ report.how[lang] }}</p>
              </div>
            </div>
          </div>
        </div>

        <!-- API Reference -->
        <div v-if="activeTab === 'api'" class="space-y-6">
          <!-- Auth -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h2 class="text-xl font-bold text-gray-900 dark:text-white mb-3">
              {{ lang === 'ar' ? '\u0627\u0644\u0645\u0635\u0627\u062F\u0642\u0629' : 'Authentication' }}
            </h2>
            <p class="text-sm text-gray-600 dark:text-gray-400 mb-3">
              {{ lang === 'ar'
                ? '\u064A\u062F\u0639\u0645 Seku \u0637\u0631\u064A\u0642\u062A\u064A\u0646 \u0644\u0644\u0645\u0635\u0627\u062F\u0642\u0629: \u0631\u0645\u0632 JWT (\u0644\u0644\u0645\u062A\u0635\u0641\u062D) \u0648\u0645\u0641\u0627\u062A\u064A\u062D API (\u0644\u0644\u0648\u0635\u0648\u0644 \u0627\u0644\u0628\u0631\u0645\u062C\u064A). \u0623\u0631\u0633\u0644 \u0627\u0644\u0631\u0645\u0632 \u0641\u064A \u0631\u0623\u0633 Authorization.'
                : 'Seku supports two authentication methods: JWT tokens (for browser) and API Keys (for programmatic access). Send the token in the Authorization header.'
              }}
            </p>
            <div class="bg-slate-900 rounded-lg p-4 font-mono text-sm text-green-400 overflow-x-auto">
              <div class="text-gray-500"># JWT Token</div>
              <div>Authorization: Bearer &lt;your-jwt-token&gt;</div>
              <div class="mt-2 text-gray-500"># API Key</div>
              <div>X-API-Key: &lt;your-api-key&gt;</div>
            </div>
          </div>

          <!-- Endpoints Table -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-4">
              {{ lang === 'ar' ? '\u0646\u0642\u0627\u0637 \u0627\u0644\u0646\u0647\u0627\u064A\u0629' : 'Endpoints' }}
            </h3>
            <div class="overflow-x-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr class="border-b border-gray-200 dark:border-slate-600 text-gray-500 dark:text-gray-400">
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0637\u0631\u064A\u0642\u0629' : 'Method' }}</th>
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0645\u0633\u0627\u0631' : 'Path' }}</th>
                    <th class="text-start pb-3 font-medium">{{ lang === 'ar' ? '\u0627\u0644\u0648\u0635\u0641' : 'Description' }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="ep in apiEndpoints" :key="ep.path + ep.method" class="border-t border-gray-100 dark:border-slate-600">
                    <td class="py-2.5">
                      <span :class="methodColor(ep.method)" class="px-2 py-0.5 rounded text-xs font-bold">{{ ep.method }}</span>
                    </td>
                    <td class="py-2.5 font-mono text-xs text-gray-900 dark:text-gray-200">{{ ep.path }}</td>
                    <td class="py-2.5 text-gray-600 dark:text-gray-400 text-xs">{{ ep.desc[lang] }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Example Requests -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-4">
              {{ lang === 'ar' ? '\u0623\u0645\u062B\u0644\u0629 \u0627\u0644\u0637\u0644\u0628\u0627\u062A' : 'Example Requests' }}
            </h3>
            <div class="space-y-4">
              <div>
                <div class="flex items-center justify-between mb-2">
                  <span class="text-sm font-medium text-gray-700 dark:text-gray-300">cURL</span>
                  <button @click="copyText(curlSnippet)" class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">{{ lang === 'ar' ? '\u0646\u0633\u062E' : 'Copy' }}</button>
                </div>
                <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-green-400 overflow-x-auto whitespace-pre">curl -X POST https://your-seku-domain/api/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_ids": [1, 2], "policy": "standard"}'</div>
              </div>
              <div>
                <div class="flex items-center justify-between mb-2">
                  <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Python</span>
                  <button @click="copyText(pythonSnippet)" class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">{{ lang === 'ar' ? '\u0646\u0633\u062E' : 'Copy' }}</button>
                </div>
                <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-green-400 overflow-x-auto whitespace-pre">import requests

resp = requests.post(
    "https://your-seku-domain/api/scans",
    headers={"X-API-Key": "YOUR_API_KEY"},
    json={"target_ids": [1, 2], "policy": "standard"}
)
print(resp.json())</div>
              </div>
              <div>
                <div class="flex items-center justify-between mb-2">
                  <span class="text-sm font-medium text-gray-700 dark:text-gray-300">JavaScript (fetch)</span>
                  <button @click="copyText(jsSnippet)" class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">{{ lang === 'ar' ? '\u0646\u0633\u062E' : 'Copy' }}</button>
                </div>
                <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-green-400 overflow-x-auto whitespace-pre">const resp = await fetch("https://your-seku-domain/api/scans", {
  method: "POST",
  headers: {
    "X-API-Key": "YOUR_API_KEY",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ target_ids: [1, 2], policy: "standard" }),
});
const data = await resp.json();
console.log(data);</div>
              </div>
            </div>
          </div>

          <!-- Rate Limits -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <h3 class="text-lg font-bold text-gray-900 dark:text-white mb-3">
              {{ lang === 'ar' ? '\u062D\u062F\u0648\u062F \u0627\u0644\u0645\u0639\u062F\u0644' : 'Rate Limits' }}
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div v-for="rl in rateLimitsData" :key="rl.plan.en" class="text-center p-3 bg-gray-50 dark:bg-slate-600 rounded-lg">
                <div class="text-sm font-semibold text-gray-900 dark:text-white">{{ rl.plan[lang] }}</div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono">{{ rl.limit }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Integrations -->
        <div v-if="activeTab === 'integrations'" class="space-y-4">
          <div v-for="integ in integrationsData" :key="integ.title.en" class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <div class="flex items-start gap-4">
              <span class="text-3xl flex-shrink-0">{{ integ.icon }}</span>
              <div>
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">{{ integ.title[lang] }}</h3>
                <p class="mt-2 text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{{ integ.desc[lang] }}</p>
              </div>
            </div>
          </div>

          <!-- GitHub Actions Example -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-lg font-bold text-gray-900 dark:text-white">
                {{ lang === 'ar' ? '\u0645\u062B\u0627\u0644 GitHub Actions' : 'GitHub Actions Example' }}
              </h3>
              <button @click="copyText(ghActionsSnippet)" class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">{{ lang === 'ar' ? '\u0646\u0633\u062E' : 'Copy' }}</button>
            </div>
            <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-green-400 overflow-x-auto whitespace-pre">name: Seku Security Check
on:
  push:
    branches: [main]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Seku
        run: |
          curl -X POST https://your-seku-domain/api/scans \
            -H "X-API-Key: $&#123;&#123; secrets.VSCAN_API_KEY &#125;&#125;" \
            -H "Content-Type: application/json" \
            -d '{ "target_ids": [1], "policy": "standard" }'</div>
          </div>

          <!-- Docker Example -->
          <div class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 p-6">
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-lg font-bold text-gray-900 dark:text-white">
                {{ lang === 'ar' ? '\u0645\u062B\u0627\u0644 Docker' : 'Docker Example' }}
              </h3>
              <button @click="copyText(dockerSnippet)" class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">{{ lang === 'ar' ? '\u0646\u0633\u062E' : 'Copy' }}</button>
            </div>
            <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-green-400 overflow-x-auto whitespace-pre">docker run -d --name seku -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host/vscan \
  -e JWT_SECRET=your-secret \
  seku:latest</div>
          </div>
        </div>

        <!-- FAQ -->
        <div v-if="activeTab === 'faq'" class="space-y-3">
          <h2 class="text-xl font-bold text-gray-900 dark:text-white mb-4">
            {{ lang === 'ar' ? '\u0627\u0644\u0623\u0633\u0626\u0644\u0629 \u0627\u0644\u0634\u0627\u0626\u0639\u0629' : 'Frequently Asked Questions' }}
          </h2>
          <div
            v-for="(faq, i) in filteredFaqs"
            :key="i"
            class="bg-white dark:bg-slate-700 rounded-xl border border-gray-200 dark:border-slate-600 overflow-hidden"
          >
            <button
              @click="toggleFaq(i)"
              class="w-full flex items-center justify-between p-5 text-start"
            >
              <span class="font-medium text-gray-900 dark:text-white">{{ faq.q[lang] }}</span>
              <svg :class="expandedFaq === i ? 'rotate-180' : ''" class="w-5 h-5 text-gray-400 transition-transform flex-shrink-0 ml-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
              </svg>
            </button>
            <div v-if="expandedFaq === i" class="px-5 pb-5 border-t border-gray-100 dark:border-slate-600 pt-4">
              <p class="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{{ faq.a[lang] }}</p>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>
</template>

<style scoped>
@media print {
  nav { display: none !important; }
  button { display: none !important; }
}
</style>
