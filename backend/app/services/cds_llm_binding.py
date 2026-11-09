"""A task capability, never a provider key or a mutable account-wide setting."""
import json
import os
from urllib.parse import urlsplit
from fastapi import HTTPException
from app.core.config import settings
from app.core.encryption import encryption_service

FIELD = '_cds_llm_binding'


def validate_binding(value):
    if not isinstance(value, dict) or set(value) != {'baseUrl', 'token', 'model'}:
        raise ValueError('Invalid CDS task binding')
    if not all(isinstance(value[k], str) and value[k] for k in value):
        raise ValueError('Invalid CDS task binding')
    base = urlsplit(value['baseUrl'])
    trusted = urlsplit(settings.LLM_BASE_URL or '')
    if (base.scheme not in ('http', 'https') or base.netloc != trusted.netloc or base.scheme != trusted.scheme
            or base.path.rstrip('/') != '/byok/v1' or base.username or base.password or base.query or base.fragment
            or not value['token'].startswith('cruk_') or len(value['token']) != 69
            or len(value['model']) > 200):
        raise ValueError('Invalid CDS task binding')
    return value


def seal_binding(raw, user):
    if not raw:
        return None
    if not os.environ.get('CDS_SERVICE_EMAIL') or user.email != os.environ['CDS_SERVICE_EMAIL']:
        raise HTTPException(status_code=403, detail='Only the dedicated CDS service may bind a task credential')
    try:
        value = validate_binding(json.loads(raw))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail='Invalid CDS task binding')
    return encryption_service.encrypt(json.dumps(value))


def apply_binding(config):
    ciphertext = config.get('scan_config', {}).get(FIELD)
    if ciphertext is None:
        return config
    if not isinstance(ciphertext, str) or not encryption_service.is_encrypted(ciphertext):
        raise ValueError('CDS task binding is unreadable; platform fallback is prohibited')
    binding = validate_binding(json.loads(encryption_service.decrypt(ciphertext)))
    # A fixed OpenAI alias prevents LiteLLM from interpreting OpenRouter's vendor/model
    # as a different transport. The gateway restores the immutable supplier model.
    config['llmConfig'] = {'llmProvider': 'openai', 'llmApiKey': binding['token'],
                           'llmBaseUrl': binding['baseUrl'], 'llmModel': 'cds-user-key-review',
                           'llmMaxTokens': 4096, 'llmTemperature': 0.1}
    return config
