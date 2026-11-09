"""Task credential isolation; runs inside the frozen CDS backend image."""
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import HTTPException
from app.core.config import settings
from app.services.cds_llm_binding import apply_binding, seal_binding, validate_binding, FIELD


class CdsLlmBindingTests(unittest.TestCase):
    def setUp(self):
        self.base = patch.object(settings, 'LLM_BASE_URL', 'https://gateway.test/v1')
        self.account = patch.dict(os.environ, {'CDS_SERVICE_EMAIL': 'service@example.invalid'})
        self.base.start(); self.account.start()
        self.binding = {'baseUrl': 'https://gateway.test/byok/v1', 'token': 'cruk_' + 'a' * 64, 'model': 'model'}

    def tearDown(self):
        self.account.stop(); self.base.stop()

    def seal(self, binding):
        return seal_binding(json.dumps(binding), SimpleNamespace(email=os.environ['CDS_SERVICE_EMAIL']))

    def test_encrypted_task_binding_does_not_mutate_the_account_config(self):
        sealed = self.seal(self.binding)
        self.assertNotIn(self.binding['token'], sealed)
        config = apply_binding({'scan_config': {FIELD: sealed}, 'llmConfig': {'llmApiKey': 'platform-key'}})
        self.assertEqual(config['llmConfig']['llmApiKey'], self.binding['token'])
        self.assertEqual(config['llmConfig']['llmProvider'], 'openai')
        self.assertEqual(config['llmConfig']['llmModel'], 'cds-user-key-review')

    def test_only_the_trusted_gateway_origin_and_path_are_allowed(self):
        for url in ['https://evil.test/byok/v1', 'https://gateway.test/v1', 'http://gateway.test/byok/v1', 'https://gateway.test/byok/v1?x=y', 'https://user@gateway.test/byok/v1']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_binding({**self.binding, 'baseUrl': url})

    def test_another_account_and_corrupt_binding_fail_closed(self):
        with self.assertRaises(HTTPException) as caught:
            seal_binding(json.dumps(self.binding), SimpleNamespace(email='other@example.invalid'))
        self.assertEqual(caught.exception.status_code, 403)
        with self.assertRaises(ValueError):
            apply_binding({'scan_config': {FIELD: 'corrupt'}, 'llmConfig': {'llmApiKey': 'platform-key'}})

    def test_vendor_model_names_always_use_the_gateway_openai_transport(self):
        from app.services.llm.service import LLMService
        from app.services.llm.adapters.litellm_adapter import LiteLLMAdapter
        for model in ['anthropic/claude-sonnet-4-5', 'openai/gpt-4.1-mini', 'deepseek/deepseek-chat']:
            with self.subTest(model=model):
                service = LLMService(apply_binding({'scan_config': {FIELD: self.seal({**self.binding, 'model': model})}}))
                adapter = LiteLLMAdapter(service.config)
                self.assertEqual(adapter._litellm_model, 'openai/cds-user-key-review')
                self.assertEqual(adapter._api_base, self.binding['baseUrl'])


if __name__ == '__main__':
    unittest.main()
