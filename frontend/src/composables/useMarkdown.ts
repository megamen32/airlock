import { computed, type Ref } from 'vue'
import DOMPurify from 'dompurify'
import { marked } from 'marked'

marked.setOptions({ gfm: true, breaks: true })

const renderer = new marked.Renderer()
renderer.link = ({ href, text }) => {
  if (!isSafeLink(href)) return text
  return `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`
}
marked.use({ renderer })

const allowedTags = [
  'a', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3', 'h4',
  'h5', 'h6', 'hr', 'img', 'li', 'ol', 'p', 'pre', 'strong', 'table',
  'tbody', 'td', 'th', 'thead', 'tr', 'ul',
]

// Relative URLs and these explicit protocols cover dashboard links while
// excluding executable and browser-local schemes such as javascript: and data:.
const allowedUri = /^(?:(?:https?|mailto|tel):|(?:[^a-z]|[a-z+.-]+(?:[^a-z+.-:]|$)))/i

function isSafeLink(href: string): boolean {
  try {
    const base = typeof window === 'undefined' ? 'https://airlock.invalid' : window.location.href
    const url = new URL(href, base)
    if (!['http:', 'https:', 'mailto:', 'tel:'].includes(url.protocol)) return false

    // These user-scoped agent paths are virtual storage, not HTTP routes.
    // A model can invent an app URL from export_document.path even after
    // air.output has delivered a real attachment. Keep the label as text;
    // the native file card is the authenticated download affordance.
    const host = new URL(base).hostname
    const localAgent = url.hostname === host || url.hostname.endsWith(`.${host}`)
    const privateFile = /\/(?:exports|workspace|__incoming)\/user-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}(?:\/|$)/i
    return !(localAgent && privateFile.test(decodeURIComponent(url.pathname)))
  } catch {
    return false
  }
}

DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.nodeName === 'A' && node.hasAttribute('href')) {
    if (!isSafeLink(node.getAttribute('href') || '')) {
      node.removeAttribute('href')
      return
    }
    node.setAttribute('target', '_blank')
    node.setAttribute('rel', 'noopener noreferrer')
  }
})

// This is the only function that turns Markdown into HTML. Every v-html call
// uses it directly or through useMarkdown below.
export function renderMarkdown(source: string): string {
  if (!source) return ''
  return DOMPurify.sanitize(marked.parse(source) as string, {
    ALLOWED_TAGS: allowedTags,
    ALLOWED_ATTR: ['alt', 'href', 'rel', 'src', 'target', 'title'],
    ALLOWED_URI_REGEXP: allowedUri,
  })
}

export function useMarkdown(source: Ref<string>) {
  const html = computed(() => renderMarkdown(source.value))

  return { html }
}
