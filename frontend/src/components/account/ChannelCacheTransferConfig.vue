<template>
  <section class="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-600 dark:bg-dark-800">
    <div class="mb-5 flex items-center gap-3">
      <span class="flex h-10 w-10 items-center justify-center rounded-full bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-300">
        <Icon name="cog" size="md" />
      </span>
      <h3 class="text-base font-semibold text-gray-900 dark:text-white">
        {{ t('admin.accounts.channelCache.title') }}
      </h3>
    </div>

    <div class="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(240px,0.65fr)]">
      <div>
        <label class="input-label">{{ t('admin.accounts.channelCache.ratio') }}</label>
        <input
          :value="ratio"
          type="number"
          min="0"
          max="100"
          step="0.1"
          class="input"
          data-testid="channel-cache-transfer-ratio"
          @input="updateRatio"
        />
        <p class="input-hint">{{ t('admin.accounts.channelCache.ratioHint') }}</p>
      </div>

      <div>
        <label class="input-label">{{ t('admin.accounts.channelCache.target') }}</label>
        <select
          :value="target"
          class="input"
          data-testid="channel-cache-transfer-target"
          @change="updateTarget"
        >
          <option value="input">{{ t('admin.accounts.channelCache.targetInput') }}</option>
          <option value="cache_creation">{{ t('admin.accounts.channelCache.targetCacheCreation') }}</option>
        </select>
        <p class="input-hint">{{ t('admin.accounts.channelCache.targetHint') }}</p>
      </div>
    </div>

    <div class="mt-5">
      <label class="input-label">{{ t('admin.accounts.channelCache.models') }}</label>
      <input
        :value="models"
        type="text"
        class="input"
        :placeholder="t('admin.accounts.channelCache.modelsPlaceholder')"
        data-testid="channel-cache-transfer-models"
        @input="updateModels"
      />
      <p class="input-hint">{{ t('admin.accounts.channelCache.modelsHint') }}</p>
    </div>

    <div class="mt-5 rounded-xl bg-gray-50 px-4 py-3 text-sm text-gray-600 dark:bg-dark-700 dark:text-gray-300">
      {{ exampleText }}
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import Icon from '@/components/icons/Icon.vue'

type ChannelCacheTransferTarget = 'input' | 'cache_creation'

const props = defineProps<{
  ratio: number
  target: ChannelCacheTransferTarget
  models: string
}>()

const emit = defineEmits<{
  (e: 'update:ratio', value: number): void
  (e: 'update:target', value: ChannelCacheTransferTarget): void
  (e: 'update:models', value: string): void
}>()

const { t } = useI18n()

const normalizedRatio = computed(() => {
  const value = Number(props.ratio)
  if (!Number.isFinite(value)) return 0
  return Math.min(100, Math.max(0, value))
})

const exampleText = computed(() => {
  const cacheWrite = 100
  const cacheRead = 10000
  const moved = Math.round((cacheRead * normalizedRatio.value) / 100)
  const remaining = cacheRead - moved
  if (props.target === 'cache_creation') {
    return t('admin.accounts.channelCache.exampleCacheCreation', {
      beforeWrite: cacheWrite,
      beforeRead: cacheRead,
      afterWrite: cacheWrite + moved,
      remaining
    })
  }
  return t('admin.accounts.channelCache.exampleInput', {
    beforeWrite: cacheWrite,
    beforeRead: cacheRead,
    moved,
    remaining
  })
})

const updateRatio = (event: Event) => {
  const value = Number((event.target as HTMLInputElement).value)
  emit('update:ratio', Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : 0)
}

const updateTarget = (event: Event) => {
  const value = (event.target as HTMLSelectElement).value
  emit('update:target', value === 'cache_creation' ? 'cache_creation' : 'input')
}

const updateModels = (event: Event) => {
  emit('update:models', (event.target as HTMLInputElement).value)
}
</script>
