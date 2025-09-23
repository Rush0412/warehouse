<template>
  <section class="card">
    <div class="card-body">
      <form class="form" @submit.prevent>
        <div class="form-grid">
          <label class="field">
            <span class="field-label">Sigma YAML</span>
            <textarea
              v-model="ruleYaml"
              class="textarea"
              rows="18"
              placeholder="将 sigma 规则粘贴到这里"
            ></textarea>
          </label>

          <div class="actions">
            <div class="action-group">
              <h3>快速操作</h3>
              <div class="buttons">
                <button type="button" class="btn primary" @click="handleParse" :disabled="isBusy">
                  解析
                </button>
                <button type="button" class="btn secondary" @click="handleValidate" :disabled="isBusy">
                  校验
                </button>
                <button type="button" class="btn accent" @click="handleConvert" :disabled="isBusy">
                  转换
                </button>
              </div>
            </div>

            <div class="field">
              <span class="field-label">目标格式</span>
              <select v-model="targetFormat" class="select" :disabled="isBusy">
                <option value="aviator">Aviator</option>
                <option value="flink_sql">Flink SQL</option>
                <option value="flink_cep">Flink CEP</option>
              </select>
            </div>

            <div class="options">
              <span class="field-label">附加参数（可选）</span>
              <textarea
                v-model="optionsText"
                class="textarea"
                rows="6"
                placeholder="JSON，例如 {\"namespace\": \"demo\"}"
              ></textarea>
            </div>

            <div class="field checkbox">
              <label>
                <input type="checkbox" v-model="useApiProxy" />
                <span>通过 <code>/api</code> 代理</span>
              </label>
            </div>
          </div>
        </div>
      </form>

      <section v-if="message" class="message" :class="message.type">
        <h3>{{ message.title }}</h3>
        <pre>{{ message.body }}</pre>
      </section>

      <section v-if="result" class="result">
        <header>
          <h3>转换结果</h3>
          <span class="badge">{{ result.format }}</span>
        </header>
        <pre>{{ result.query }}</pre>
      </section>

      <section v-if="validation" class="validation" :class="{ success: validation.valid, error: !validation.valid }">
        <header>
          <h3>校验结果</h3>
          <span class="badge">{{ validation.valid ? "通过" : "未通过" }}</span>
        </header>
        <ul v-if="validation.errors && validation.errors.length">
          <li v-for="(error, index) in validation.errors" :key="index">{{ error }}</li>
        </ul>
      </section>

      <section v-if="parsed" class="parsed">
        <header>
          <h3>解析结果</h3>
        </header>
        <pre>{{ parsed }}</pre>
      </section>
    </div>
  </section>
</template>

<script setup>
import { computed, ref } from "vue";

const props = defineProps({
  apiBaseUrl: {
    type: String,
    required: true
  }
});

const ruleYaml = ref(`title: Suspicious Process Creation
id: 123e4567-e89b-12d3-a456-426614174000
description: Example sigma rule for演示
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: powershell.exe
  condition: selection
level: high`);
const targetFormat = ref("aviator");
const optionsText = ref("{}");
const isBusy = ref(false);
const message = ref(null);
const result = ref(null);
const validation = ref(null);
const parsed = ref(null);
const useApiProxy = ref(true);

const endpointBase = computed(() => {
  if (useApiProxy.value) {
    return "/api";
  }
  return props.apiBaseUrl.replace(/\/$/, "");
});

function buildOptions() {
  if (!optionsText.value.trim()) {
    return {};
  }
  try {
    return JSON.parse(optionsText.value);
  } catch (error) {
    throw new Error("附加参数必须是合法的 JSON 字符串");
  }
}

async function request(path, init) {
  const url = `${endpointBase.value}${path}`;
  const headers = { "Content-Type": "application/json" };
  const response = await fetch(url, { ...init, headers });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail?.message || detail?.detail || response.statusText);
  }
  return response.json();
}

function resetOutputs() {
  message.value = null;
  result.value = null;
  validation.value = null;
  parsed.value = null;
}

async function handleParse() {
  isBusy.value = true;
  resetOutputs();
  try {
    const data = await request("/rules/parse", {
      method: "POST",
      body: JSON.stringify({ rule_yaml: ruleYaml.value })
    });
    parsed.value = JSON.stringify(data.parsed, null, 2);
    message.value = { type: "success", title: "解析成功", body: "已生成结构化 JSON" };
  } catch (error) {
    message.value = { type: "error", title: "解析失败", body: error.message };
  } finally {
    isBusy.value = false;
  }
}

async function handleValidate() {
  isBusy.value = true;
  resetOutputs();
  try {
    const data = await request("/rules/validate", {
      method: "POST",
      body: JSON.stringify({ rule_yaml: ruleYaml.value })
    });
    validation.value = data;
    message.value = {
      type: data.valid ? "success" : "warning",
      title: data.valid ? "校验通过" : "校验存在问题",
      body: data.errors?.join("\n") || "规则符合要求"
    };
  } catch (error) {
    message.value = { type: "error", title: "校验失败", body: error.message };
  } finally {
    isBusy.value = false;
  }
}

async function handleConvert() {
  isBusy.value = true;
  resetOutputs();
  try {
    const options = buildOptions();
    const data = await request("/rules/convert", {
      method: "POST",
      body: JSON.stringify({
        payload: { rule_yaml: ruleYaml.value },
        target_format: targetFormat.value,
        options
      })
    });
    result.value = data;
    message.value = { type: "success", title: "转换成功", body: "见下方结果" };
  } catch (error) {
    message.value = { type: "error", title: "转换失败", body: error.message };
  } finally {
    isBusy.value = false;
  }
}
</script>

<style scoped>
.card {
  background: #ffffff;
  border-radius: 1rem;
  box-shadow: 0 20px 45px -30px rgba(15, 23, 42, 0.4);
  padding: 2rem;
}

.form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-grid {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 1.5rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.field-label {
  font-weight: 600;
  color: #1e293b;
}

.textarea,
.select {
  width: 100%;
  border-radius: 0.75rem;
  border: 1px solid #cbd5f5;
  padding: 0.75rem;
  font-size: 0.95rem;
  resize: vertical;
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  background: #f8fafc;
}

.select {
  background: #ffffff;
}

.actions {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.action-group h3 {
  margin: 0;
  font-size: 1rem;
  color: #0f172a;
}

.buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.btn {
  padding: 0.6rem 1.2rem;
  border-radius: 999px;
  border: none;
  font-weight: 600;
  font-size: 0.95rem;
  color: #ffffff;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.btn.primary {
  background: linear-gradient(135deg, #2563eb, #7c3aed);
  box-shadow: 0 12px 30px -15px rgba(79, 70, 229, 0.8);
}

.btn.secondary {
  background: linear-gradient(135deg, #059669, #22d3ee);
  box-shadow: 0 12px 30px -15px rgba(13, 148, 136, 0.8);
}

.btn.accent {
  background: linear-gradient(135deg, #f97316, #ef4444);
  box-shadow: 0 12px 30px -15px rgba(251, 146, 60, 0.8);
}

.btn:disabled {
  cursor: not-allowed;
  opacity: 0.6;
  transform: none;
  box-shadow: none;
}

.btn:not(:disabled):hover {
  transform: translateY(-1px);
}

.options {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.checkbox label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #475569;
}

.message {
  margin-top: 2rem;
  border-radius: 0.75rem;
  padding: 1rem 1.25rem;
  background: #f8fafc;
  border: 1px solid #cbd5f5;
}

.message.success {
  border-color: rgba(34, 197, 94, 0.6);
  background: rgba(220, 252, 231, 0.6);
}

.message.warning {
  border-color: rgba(234, 179, 8, 0.6);
  background: rgba(254, 243, 199, 0.6);
}

.message.error {
  border-color: rgba(248, 113, 113, 0.6);
  background: rgba(254, 226, 226, 0.6);
}

.message pre {
  margin: 0.5rem 0 0;
  white-space: pre-wrap;
}

.result,
.validation,
.parsed {
  margin-top: 2rem;
  padding: 1.5rem;
  border-radius: 0.75rem;
  background: #0f172a;
  color: #e2e8f0;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.result header,
.validation header,
.parsed header {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  font-size: 0.8rem;
  font-weight: 600;
  color: #0f172a;
  background: #f1f5f9;
}

.result pre,
.parsed pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.validation ul {
  margin: 0;
  padding-left: 1.3rem;
}

.validation.success {
  background: #022c22;
  color: #d1fae5;
}

.validation.success .badge {
  background: rgba(16, 185, 129, 0.2);
  color: #0f766e;
}

.validation.error {
  background: #450a0a;
  color: #fecaca;
}

.validation.error .badge {
  background: rgba(239, 68, 68, 0.2);
  color: #fee2e2;
}

@media (max-width: 960px) {
  .form-grid {
    grid-template-columns: 1fr;
  }
}
</style>
