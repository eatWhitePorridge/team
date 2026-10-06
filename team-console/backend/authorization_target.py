"""Validate an optional OAuth target before enqueueing, using local metadata only."""
import re

_WORKSPACE_ID = re.compile(r'[A-Za-z0-9_-]{1,200}')


def authorization_workspace(data, *, team, store):
    has_workspace = 'expected_workspace_id' in data
    has_parent = 'parent_id' in data
    if not has_workspace and not has_parent:
        # Existing clients and ordinary authorization retain their old behavior.
        return ''
    if not team:
        raise ValueError('只有 Team 授权支持指定目标工作区')
    value = data.get('expected_workspace_id')
    if not isinstance(value, str) or not _WORKSPACE_ID.fullmatch(value.strip()):
        raise ValueError('请填写有效的工作区 ID（1–200 位字母、数字、下划线或连字符）')
    workspace_id = value.strip()
    if has_parent:
        parent_id = data['parent_id']
        if type(parent_id) is not int or parent_id <= 0:
            raise ValueError('请选择有效母号')
        # This is OAuth for the selected children, NOT a mother-account mutation.
        # A read-only mother workspace is still a valid authorization target.
        if not any(row['id'] == workspace_id for row in store.workspaces(parent_id)):
            raise ValueError('工作区不属于所选母号或缓存已变化，请重新选择或同步母号工作区')
    return workspace_id
