// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { renderMarkdown } from './useMarkdown'

const privatePath = '/exports/user-00000000-0000-4000-8000-000000000123/memo.md'
const appOrigin = `${window.location.protocol}//exmanager.${window.location.host}`

describe('native file links', () => {
  it.each([
    privatePath,
    privatePath.slice(1),
    `${window.location.origin}${privatePath}`,
    `${appOrigin}${privatePath}`,
    `${appOrigin}${privatePath.replace('exports', '%65xports')}`,
    privatePath.replace('/exports/', '/workspace/'),
    privatePath.replace('/exports/', '/__incoming/'),
  ])('does not present a private virtual file path as a download: %s', (href) => {
    const html = renderMarkdown(`[memo.md](${href})`)
    expect(html).toContain('memo.md')
    expect(html).not.toContain('<a ')
    expect(html).not.toContain('href=')
  })

  it('also removes an invented download target from raw HTML', () => {
    const html = renderMarkdown(`<a href="${appOrigin}${privatePath}">memo.md</a>`)
    expect(html).toContain('memo.md')
    expect(html).not.toContain('href=')
  })

  it.each([
    'https://docs.example.org/files/memo.md',
    `https://external.example.org${privatePath}`,
    '/exports/public-report.md',
    '/api/v1/conversations/test/files?source=opaque-file-id',
    'mailto:editor@example.org',
  ])('preserves normal references and real file routes: %s', (href) => {
    expect(renderMarkdown(`[reference](${href})`)).toContain('<a ')
  })

  it('keeps storage paths quoted as code for diagnostic explanations', () => {
    const html = renderMarkdown('`' + privatePath + '`')
    expect(html).toContain(`<code>${privatePath}</code>`)
  })
})
