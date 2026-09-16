// @vitest-environment jsdom
import { mount, flushPromises } from '@vue/test-utils'
import { afterEach, expect, it, vi } from 'vitest'
import MessageParts from './MessageParts.vue'
import api from '@/api/client'

vi.mock('@/api/client', () => ({ default: { get: vi.fn() } }))
vi.mock('@/i18n', () => ({ useAirlockI18n: () => ({ t: (key: string) => key }) }))

afterEach(() => vi.restoreAllMocks())

it('downloads a conversation file through the authenticated client', async () => {
  const blob = new Blob(['720 ₽; пятница'])
  vi.mocked(api.get).mockResolvedValueOnce({ data: blob })
  const create = vi.fn(() => 'blob:fixture')
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: create })
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() })
  const save = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  const url = '/api/v1/conversations/conversation/files?source=agents%2Fapp%2Fmedia%2Fmemo.md'
  const wrapper = mount(MessageParts, { props: { parts: [{ type: 'file', filename: 'memo.md', url }] } })
  await wrapper.get('a.part-file').trigger('click')
  await flushPromises()
  expect(api.get).toHaveBeenCalledWith(url, { responseType: 'blob' })
  expect(create).toHaveBeenCalledWith(blob)
  expect(save).toHaveBeenCalledOnce()
  expect(wrapper.find('[role="alert"]').exists()).toBe(false)
})

it('shows failure without claiming a download or exposing the backend error', async () => {
  vi.mocked(api.get).mockRejectedValueOnce(new Error('PRIVATE upstream detail'))
  const wrapper = mount(MessageParts, { props: { parts: [{ type: 'file', filename: 'memo.md', url: '/api/v1/conversations/c/files?source=x' }] } })
  await wrapper.get('a.part-file').trigger('click')
  await flushPromises()
  expect(wrapper.get('[role="alert"]').text()).toBe('chat.file.downloadFailed')
  expect(wrapper.text()).not.toContain('PRIVATE')
})
