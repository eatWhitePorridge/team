"""Explicit plaintext backup. Credentials never enter the read index or logs."""
from datetime import datetime, timezone
import re


def export_accounts(db, account_ids):
    from core.codex_password_totp import login_material, PasswordTotpLoginError

    candidates = db.get_account_totp_export_candidates(account_ids)
    lines, failed = [], []
    unverified = 0
    for account_id in account_ids:
        row = candidates.get(account_id)
        email = str((row or {}).get('email') or '').strip()
        valid_email = len(email) <= 254 and '----' not in email and bool(re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email))
        label = {'account_id': account_id, 'email': email if valid_email else ''}
        try:
            if row is None or row.get('archived'):
                raise ValueError('账号不存在或已归档')
            if not valid_email:
                raise ValueError('邮箱格式无效，无法导出三段式')
            password, secret = login_material(row)
            if any(char in password for char in '\x00\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029'):
                raise ValueError('密码包含无法写入三段式的换行或控制字符')
            lines.append(f'{email}----{password}----{secret}')
            if str(row.get('totp_status') or '').lower() not in {'active', 'active_external'}:
                unverified += 1
        except (PasswordTotpLoginError, ValueError) as exc:
            # These validators use fixed messages, never the credential value.
            failed.append({**label, 'error': str(exc)})
    warnings = [{'error': f'{unverified} 个账号的 2FA 密钥尚未验证；已按保存值导出，未改变账号状态'}] if unverified else []
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    return {'ok': bool(lines), 'requested_count': len(account_ids), 'exported_count': len(lines),
            'failed_count': len(failed), 'failed': failed, 'warnings': warnings,
            'filename': f'2fa-{stamp}.txt', 'data': '\n'.join(lines) + ('\n' if lines else '')}
