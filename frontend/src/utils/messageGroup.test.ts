import { describe, expect, it } from 'vitest'
import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'
import { enrichMessages } from './messageGroup'

function row(id: string, parts: unknown[], extra = {}): AgentMessageInfo {
  return { id, role: 'assistant', source: 'user', runId: 'run-1', content: '', parts: JSON.stringify(parts), ...extra } as AgentMessageInfo
}

describe('native conversation output', () => {
  it('keeps delivered media when folding it between tool steps and the final reply', () => {
    const file = { type: 'file', source: 'agents/app/media/memo.md', url: 'https://files.example/memo.md', filename: 'memo.md', text: 'Payment memo' }
    const messages = enrichMessages([
      row('start', [{ type: 'tool-call', toolCallId: 'export', toolName: 'run_js', args: {} }]),
      row('output', [file], { content: '[memo.md] Payment memo' }),
      row('step', [{ type: 'tool-call', toolCallId: 'output', toolName: 'run_js', args: {} }]),
      row('final', [{ type: 'text', text: 'Attached.' }]),
    ])
    const blocks = (messages[0] as any).blocks
    expect(blocks.map((b: any) => b.kind)).toEqual(['tool', 'media', 'tool', 'text'])
    expect(blocks[1].parts).toEqual([file])
    expect((messages[1] as any)._hidden).toBe(true)
  })

  it('renders standalone assistant media and keeps private reasoning and tool attachments out', () => {
    const video = { type: 'video', url: 'https://files.example/video.mp4' }
    const messages = enrichMessages([
      row('media', [{ type: 'reasoning', text: 'PRIVATE' }, video], { runId: '' }),
      row('private', [{ type: 'file', url: 'https://files.example/private' }], { source: 'llm' }),
    ])
    expect((messages[0] as any).blocks).toEqual([{ kind: 'media', parts: [video] }])
    expect((messages[1] as any)._hidden).toBe(true)
    expect((messages[1] as any).blocks).toBeUndefined()
  })
})
