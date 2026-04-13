/**
 * useSEO — Dynamic meta tag management for Vue Router pages
 * Sets title, description, canonical, and OpenGraph tags per route
 */
import { onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'

const SITE_NAME = 'Seku - سيكو'
const SITE_URL = 'https://sec.erticaz.com'
const DEFAULT_IMAGE = `${SITE_URL}/og-image.png`

function setMeta(name, content, attr = 'name') {
  if (!content) return
  let tag = document.querySelector(`meta[${attr}="${name}"]`)
  if (!tag) {
    tag = document.createElement('meta')
    tag.setAttribute(attr, name)
    document.head.appendChild(tag)
  }
  tag.setAttribute('content', content)
}

function setLink(rel, href) {
  let link = document.querySelector(`link[rel="${rel}"]`)
  if (!link) {
    link = document.createElement('link')
    link.setAttribute('rel', rel)
    document.head.appendChild(link)
  }
  link.setAttribute('href', href)
}

/**
 * Use SEO for current page
 * @param {Object} options - { title, description, keywords, image, type, noindex }
 */
export function useSEO(options = {}) {
  const route = useRoute()

  function apply(opts) {
    const {
      title = '',
      description = '',
      keywords = '',
      image = DEFAULT_IMAGE,
      type = 'website',
      noindex = false,
    } = opts

    // Title
    const fullTitle = title ? `${title} | ${SITE_NAME}` : SITE_NAME
    document.title = fullTitle

    // Standard meta
    setMeta('description', description)
    if (keywords) setMeta('keywords', keywords)
    setMeta('robots', noindex ? 'noindex, nofollow' : 'index, follow')

    // Canonical URL
    const canonical = `${SITE_URL}${route.path}`
    setLink('canonical', canonical)

    // OpenGraph
    setMeta('og:title', fullTitle, 'property')
    setMeta('og:description', description, 'property')
    setMeta('og:url', canonical, 'property')
    setMeta('og:image', image, 'property')
    setMeta('og:type', type, 'property')

    // Twitter
    setMeta('twitter:title', fullTitle)
    setMeta('twitter:description', description)
    setMeta('twitter:image', image)
  }

  onMounted(() => apply(options))
  watch(() => route.path, () => apply(options))

  return { apply }
}
