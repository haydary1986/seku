/**
 * useAnalytics — Google Analytics 4 integration for Vue Router
 *
 * Loads gtag.js dynamically based on admin SEO settings.
 * Tracks page views on every route change.
 * Privacy-friendly: only loads if GA ID is configured.
 */

let gaLoaded = false
let gaID = null
let verificationTagsAdded = false

/**
 * Initialize Google Analytics if configured.
 * Should be called once on app startup.
 */
export async function initAnalytics(router) {
  try {
    const res = await fetch('/api/seo/public')
    if (!res.ok) return
    const config = await res.json()

    // Add Google Search Console verification tag
    if (config.google_search_console && !verificationTagsAdded) {
      addMetaTag('google-site-verification', config.google_search_console)
    }

    // Add Bing verification tag
    if (config.bing_verification && !verificationTagsAdded) {
      addMetaTag('msvalidate.01', config.bing_verification)
    }

    // Add Facebook App ID
    if (config.facebook_app_id && !verificationTagsAdded) {
      addMetaTag('fb:app_id', config.facebook_app_id, 'property')
    }

    verificationTagsAdded = true

    // Load Google Analytics
    if (config.google_analytics && !gaLoaded) {
      loadGoogleAnalytics(config.google_analytics)
      setupRouteTracking(router)
    }
  } catch (e) {
    console.warn('Failed to load SEO config:', e)
  }
}

function addMetaTag(name, content, attr = 'name') {
  if (document.querySelector(`meta[${attr}="${name}"]`)) return
  const tag = document.createElement('meta')
  tag.setAttribute(attr, name)
  tag.setAttribute('content', content)
  document.head.appendChild(tag)
}

function loadGoogleAnalytics(measurementID) {
  gaID = measurementID
  gaLoaded = true

  // Inject gtag.js script
  const script = document.createElement('script')
  script.async = true
  script.src = `https://www.googletagmanager.com/gtag/js?id=${measurementID}`
  document.head.appendChild(script)

  // Initialize dataLayer and gtag
  window.dataLayer = window.dataLayer || []
  window.gtag = function () {
    window.dataLayer.push(arguments)
  }
  window.gtag('js', new Date())
  window.gtag('config', measurementID, {
    send_page_view: true,
    anonymize_ip: true, // Privacy-friendly
  })

  console.log('[Analytics] Google Analytics loaded:', measurementID)
}

function setupRouteTracking(router) {
  router.afterEach((to) => {
    if (!gaLoaded || !window.gtag) return
    window.gtag('event', 'page_view', {
      page_path: to.fullPath,
      page_title: document.title,
      page_location: window.location.href,
    })
  })
}

/**
 * Track custom event manually.
 * Usage: trackEvent('scan_started', { plan: 'pro', target_count: 5 })
 */
export function trackEvent(eventName, params = {}) {
  if (!gaLoaded || !window.gtag) return
  window.gtag('event', eventName, params)
}
