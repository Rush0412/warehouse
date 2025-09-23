<template>
  <div class="layout">
    <header class="page-header">
      <div>
        <h1>Sigma 规则测试台</h1>
        <p>录入 YAML 后即可调用 FastAPI 服务，快速查看解析、校验与转换结果。</p>
      </div>
      <div class="api-config">
        <label class="field">
          <span>后端地址</span>
          <input v-model="apiBaseUrl" type="text" placeholder="http://localhost:8000" />
        </label>
      </div>
    </header>

    <main class="content">
      <SigmaForm :api-base-url="apiBaseUrl" />
    </main>

    <footer class="page-footer">
      <p>
        该页面仅用于本地测试，配合 <code>pysigma</code> 后端即可完成端到端调试。
      </p>
    </footer>
  </div>
</template>

<script setup>
import { ref } from "vue";
import SigmaForm from "./components/SigmaForm.vue";

const apiBaseUrl = ref("http://localhost:8000");
</script>

<style scoped>
.layout {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2.5rem 1.5rem 3rem;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  gap: 2rem;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 2rem;
}

.page-header h1 {
  margin: 0 0 0.5rem;
  font-size: 2rem;
}

.page-header p {
  margin: 0;
  max-width: 52ch;
  color: #475569;
}

.api-config {
  min-width: 260px;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  font-size: 0.9rem;
  color: #334155;
}

.field input {
  padding: 0.5rem 0.75rem;
  border: 1px solid #cbd5f5;
  border-radius: 0.5rem;
  font-size: 0.95rem;
}

.content {
  flex: 1 1 auto;
}

.page-footer {
  font-size: 0.85rem;
  color: #94a3b8;
  text-align: center;
}

.page-footer code {
  background-color: #e2e8f0;
  border-radius: 0.3rem;
  padding: 0.2rem 0.4rem;
}

@media (max-width: 900px) {
  .page-header {
    flex-direction: column;
  }

  .api-config {
    width: 100%;
  }
}
</style>
