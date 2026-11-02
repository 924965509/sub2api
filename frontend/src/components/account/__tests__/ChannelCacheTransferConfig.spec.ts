import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ChannelCacheTransferConfig from '../ChannelCacheTransferConfig.vue'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string, params?: Record<string, unknown>) => {
        if (!params) return key
        return `${key}:${JSON.stringify(params)}`
      }
    })
  }
})

describe('ChannelCacheTransferConfig', () => {
  it('binds ratio, target, and model rules', async () => {
    const wrapper = mount(ChannelCacheTransferConfig, {
      props: {
        ratio: 25,
        target: 'input',
        models: 'claude-opus-*'
      },
      global: {
        stubs: { Icon: true }
      }
    })

    expect((wrapper.get('[data-testid="channel-cache-transfer-ratio"]').element as HTMLInputElement).value).toBe('25')
    expect((wrapper.get('[data-testid="channel-cache-transfer-target"]').element as HTMLSelectElement).value).toBe('input')
    expect((wrapper.get('[data-testid="channel-cache-transfer-models"]').element as HTMLInputElement).value).toBe('claude-opus-*')

    await wrapper.get('[data-testid="channel-cache-transfer-ratio"]').setValue('40')
    expect(wrapper.emitted('update:ratio')?.at(-1)).toEqual([40])

    await wrapper.get('[data-testid="channel-cache-transfer-target"]').setValue('cache_creation')
    expect(wrapper.emitted('update:target')?.at(-1)).toEqual(['cache_creation'])

    await wrapper.get('[data-testid="channel-cache-transfer-models"]').setValue('claude-opus-*,gpt-5.6-terra')
    expect(wrapper.emitted('update:models')?.at(-1)).toEqual(['claude-opus-*,gpt-5.6-terra'])
  })

  it('clamps invalid ratios before emitting them', async () => {
    const wrapper = mount(ChannelCacheTransferConfig, {
      props: { ratio: 0, target: 'input', models: '' },
      global: { stubs: { Icon: true } }
    })

    await wrapper.get('[data-testid="channel-cache-transfer-ratio"]').setValue('150')
    expect(wrapper.emitted('update:ratio')?.at(-1)).toEqual([100])

    await wrapper.get('[data-testid="channel-cache-transfer-ratio"]').setValue('-4')
    expect(wrapper.emitted('update:ratio')?.at(-1)).toEqual([0])
  })
})
