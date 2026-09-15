import { describe, expect, it } from 'vitest'
import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'
import { enrichMessages } from './messageGroup'

describe('enrichMessages', () => {
  it('removes a provider <think> block from a plain final assistant reply', () => {
    const messages = [
      {
        id: 'assistant-final',
        role: 'assistant',
        source: 'user',
        content: '<think>Let me formulate the result for the user.</think>\n\nГотово: задача сохранена.',
      },
    ] as unknown as AgentMessageInfo[]

    enrichMessages(messages)

    expect(messages[0].content).toBe('Готово: задача сохранена.')
  })

  it('hides planning text from a tool-calling step but preserves the final answer', () => {
    const messages = [
      {
        id: 'assistant-tool-step',
        role: 'assistant',
        source: 'user',
        runId: 'run-1',
        content: 'I will run JavaScript: return await tools.create_task(...)',
        parts: JSON.stringify([
          { type: 'text', text: 'I will run JavaScript: return await tools.create_task(...)' },
          { type: 'tool-call', toolCallId: 'call-1', toolName: 'run_js', args: { description: 'Create a task' } },
        ]),
      },
      {
        id: 'tool-result',
        role: 'tool',
        content: '{"id":"task-1"}',
        parts: JSON.stringify([
          { type: 'tool-result', toolCallId: 'call-1', toolName: 'run_js', output: { type: 'json', value: { id: 'task-1' } } },
        ]),
      },
      {
        id: 'assistant-final-step',
        role: 'assistant',
        source: 'user',
        runId: 'run-1',
        content: 'Задача создана на завтра.',
        parts: JSON.stringify([{ type: 'text', text: 'Задача создана на завтра.' }]),
      },
    ] as unknown as AgentMessageInfo[]

    enrichMessages(messages)

    const anchor = messages[0] as any
    expect(anchor.content).toBe('Задача создана на завтра.')
    expect(anchor.blocks).toHaveLength(2)
    expect(anchor.blocks[0]).toMatchObject({ kind: 'tool', description: 'Create a task' })
    expect(anchor.blocks[1]).toEqual({ kind: 'text', text: 'Задача создана на завтра.' })
    expect(JSON.stringify(anchor.blocks)).not.toContain('return await tools.create_task')
    expect((messages[1] as any)._hidden).toBe(true)
    expect((messages[2] as any)._hidden).toBe(true)
  })
})
