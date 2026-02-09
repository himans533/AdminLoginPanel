import pytest
import os, sys
# Ensure project package is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, valid_tokens
from datetime import datetime


def test_logout_invalidates_token_and_clears_session():
    client = app.test_client()
    test_token = 'test-token-123'

    # Insert token into valid_tokens and set session
    valid_tokens[test_token] = {'user_id': 1, 'username': 'rishi', 'created_at': datetime.now(), 'csrf_token': 'csrf-abc'}

    with client.session_transaction() as sess:
        sess['auth_token'] = test_token
        sess['user_id'] = 1
        sess['is_authenticated'] = True
        sess['csrf_token'] = 'csrf-abc'

    res = client.post('/api/user/logout', headers={'Authorization': f'Bearer {test_token}', 'X-CSRF-Token': 'csrf-abc'})
    assert res.status_code == 200
    assert test_token not in valid_tokens

    # Session should be cleared
    with client.session_transaction() as sess:
        assert not sess.get('is_authenticated')


def test_cannot_create_super_admin_username():
    client = app.test_client()

    with client.session_transaction() as sess:
        sess['user_type'] = 'admin'
        sess['is_authenticated'] = True
        sess['csrf_token'] = 'sess-csrf'

    payload = {
        'username': 'Super Admin',
        'email': 'fake@example.com',
        'password': 'SecurePass1!',
        'confirm_password': 'SecurePass1!',
        'user_type_id': 1
    }

    res = client.post('/api/users', json=payload, headers={'X-CSRF-Token': 'sess-csrf'})
    assert res.status_code == 400
    data = res.get_json()
    assert 'reserved' in (data.get('error') or '').lower()
