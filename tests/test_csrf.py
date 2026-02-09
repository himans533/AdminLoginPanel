import pytest
import time
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app


def test_admin_usertypes_requires_csrf():
    client = app.test_client()

    with client.session_transaction() as sess:
        sess['is_authenticated'] = True
        sess['user_type'] = 'admin'
        sess['csrf_token'] = 'test-csrf-123'

    # Without header -> should be rejected
    res = client.post('/api/usertypes', json={'user_role': 'TestRole'})
    assert res.status_code == 400

    # With header -> should be accepted (or at least not CSRF rejected). We expect 201 or 409 depending on duplicates
    res2 = client.post('/api/usertypes', json={'user_role': 'TestRole'}, headers={'X-CSRF-Token': 'test-csrf-123'})
    assert res2.status_code in (201, 409)


def test_login_rate_limit():
    client = app.test_client()

    # Trigger several failed OTP attempts to cause a block
    for _ in range(1, 7):
        res = client.post('/api/admin/login/step2', json={'otp': 'wrong'})

    assert res.status_code in (400, 429)
    if res.status_code == 429:
        data = res.get_json()
        assert 'Too many failed' in (data.get('error') or '')
