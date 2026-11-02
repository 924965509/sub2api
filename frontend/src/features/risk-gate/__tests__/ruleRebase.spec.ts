import { describe, expect, it } from 'vitest'
import { rebaseRuleDraft } from '../viewModel'
import type { Rule } from '../types'
const make = (id: number, pattern = `rule_${id}`): Rule => ({ id, rule_key: `custom-${id}`, gate: 'regex', category: 'custom', pattern, is_regex: false, action: 'block', enabled: true, sort_order: id, description: '' })
describe('rule-set conflict rebase', () => {
  it('keeps remote additions and unrelated remote edits alongside local changes', () => {
    const base = [make(1), make(2)]
    const local = [{ ...make(1), enabled: false }, make(2)]
    const remote = [{ ...make(1), description: 'remote description' }, make(2, 'remote_pattern'), make(3)]
    const merged = rebaseRuleDraft(base, local, remote)
    expect(merged).toHaveLength(3)
    expect(merged[0]).toMatchObject({ id: 1, enabled: false, description: 'remote description' })
    expect(merged[1].pattern).toBe('remote_pattern')
    expect(merged[2].id).toBe(3)
  })
  it('does not resurrect an unchanged rule removed by another administrator', () => {
    expect(rebaseRuleDraft([make(1)], [make(1)], [])).toEqual([])
  })
  it('keeps intentional local deletion while preserving a remote addition', () => {
    expect(rebaseRuleDraft([make(1)], [], [make(1), make(2)]).map(rule => rule.id)).toEqual([2])
  })
  it('keeps a locally edited remotely deleted rule as a new draft', () => {
    const result = rebaseRuleDraft([make(1)], [make(1, 'edited')], [])
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({ pattern: 'edited', id: undefined })
  })
})
