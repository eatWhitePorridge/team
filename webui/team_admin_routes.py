"""Authenticated routes for the independent Team owner management surface."""
import logging

from flask import Blueprint, jsonify, request

from core import team_admin_service as service, team_admin_store as store

logger = logging.getLogger(__name__)
blueprint = Blueprint("team_admin", __name__, url_prefix="/api/team-admin")


def _body():
    # Member removal intentionally has no count limit. Keep a generous body
    # ceiling for large ID selections while still rejecting accidental uploads.
    if (request.content_length or 0) > 4 * 1024 * 1024:
        raise store.TeamAdminError("请求内容过大", status=413)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise store.TeamAdminError("请求必须是 JSON 对象")
    return data


@blueprint.errorhandler(store.TeamAdminError)
def expected_error(exc):
    return jsonify({"ok": False, "error": str(exc), "code": exc.code}), exc.status


@blueprint.errorhandler(Exception)
def unexpected_error(exc):
    logger.error("[母号管理 API] %s", type(exc).__name__)
    return jsonify({"ok": False, "error": "母号管理处理失败，请检查本地存储和服务日志"}), 500


@blueprint.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@blueprint.get("/parents")
def list_parents():
    return jsonify({"items": store.list_parents()})


@blueprint.post("/invite-targets")
def invite_targets():
    return jsonify(service.invite_account_targets(_body()))


@blueprint.post("/parents/<int:parent_id>/invite-accounts")
def invite_accounts(parent_id):
    return jsonify({"ok": True, "job": service.enqueue_account_invitations(parent_id, _body())}), 202


@blueprint.post("/parents/<int:parent_id>/remove-accounts/preview")
def preview_account_removal(parent_id):
    from core import team_account_removal
    return jsonify(team_account_removal.preview(parent_id, _body()))


@blueprint.post("/parents/<int:parent_id>/remove-accounts")
def remove_accounts(parent_id):
    from core import team_account_removal
    return jsonify({"ok": True, "job": team_account_removal.enqueue(parent_id, _body())}), 202


@blueprint.post("/parents/<int:parent_id>/switch-accounts/preview")
def preview_account_switch(parent_id):
    from core import team_account_switch
    return jsonify(team_account_switch.preview(parent_id, _body()))


@blueprint.post("/parents/<int:parent_id>/switch-accounts")
def switch_accounts(parent_id):
    from core import team_account_switch
    return jsonify({"ok": True, "job": team_account_switch.enqueue(parent_id, _body())}), 202


@blueprint.post("/parents/<int:parent_id>/schedule-preview")
def schedule_preview(parent_id):
    from core import team_schedule_service
    return jsonify(team_schedule_service.preview(parent_id, _body()))


@blueprint.post("/parents/<int:parent_id>/schedule")
def schedule(parent_id):
    from core import team_schedule_service
    return jsonify({"ok": True, "job": team_schedule_service.enqueue(parent_id, _body())}), 202


@blueprint.post("/parents")
def add_parent():
    return jsonify({"ok": True, "item": service.add_parent(_body())}), 201


@blueprint.get("/parents/<int:parent_id>")
def parent_detail(parent_id):
    return jsonify({"item": store.get_parent(parent_id), "workspaces": store.workspaces(parent_id), "jobs": store.recent_jobs(parent_id)})


@blueprint.post("/parents/<int:parent_id>/workspaces/<workspace_id>/subscription-expiration")
def subscription_expiration(parent_id, workspace_id):
    return jsonify({"workspace": service.check_workspace_expiration(parent_id, workspace_id)})


@blueprint.patch("/parents/<int:parent_id>")
def edit_parent(parent_id):
    return jsonify({"ok": True, "item": service.edit_parent(parent_id, _body())})


@blueprint.post("/parents/<int:parent_id>/proxy")
def set_parent_proxy(parent_id):
    return jsonify({"ok": True, "item": service.set_parent_proxy(parent_id, _body())})


@blueprint.delete("/parents/<int:parent_id>")
def delete_parent(parent_id):
    # Retain the existing bodyless DELETE contract for older clients.
    # New confirmations carry an identity guard; never silently ignore it.
    expected_email = None
    if request.get_data(cache=True):
        data = _body()
        if data.get("confirm") is not True:
            raise store.TeamAdminError("请先确认删除母号")
        expected_email = data.get("expected_email")
        if not isinstance(expected_email, str) or not expected_email.strip():
            raise store.TeamAdminError("缺少待删除母号邮箱，请刷新后重试")
    store.delete_parent(parent_id, expected_email=expected_email)
    return jsonify({"ok": True})


@blueprint.get("/parents/<int:parent_id>/workspaces/<workspace_id>/members")
@blueprint.post("/parents/<int:parent_id>/workspaces/<workspace_id>/members/search")
def members(parent_id, workspace_id):
    args = _body() if request.method == "POST" else request.args
    if any(isinstance(value, (dict, list)) for value in args.values()):
        raise store.TeamAdminError("搜索参数必须是文本或数字，邮箱需一行一个")
    return _cached_page(
        parent_id, workspace_id, service.member_page_with_quota,
        params=args,
        allow_all=True,
        emails=args.get("emails", ""),
        email_status=args.get("email_status", ""),
        seat_type=args.get("seat_type", ""),
        seat_status=args.get("seat_status", ""),
    )


@blueprint.post("/parents/<int:parent_id>/workspaces/<workspace_id>/members/check-quota")
def check_member_quota(parent_id, workspace_id):
    return jsonify(service.enqueue_member_quota_check(parent_id, workspace_id, _body())), 202


@blueprint.get("/parents/<int:parent_id>/workspaces/<workspace_id>/invites")
def invites(parent_id, workspace_id):
    return _cached_page(parent_id, workspace_id, store.invite_page, allow_all=True,
                        seat_type=request.args.get("seat_type", ""), status=request.args.get("status", ""))


def _cached_page(parent_id, workspace_id, read_page, *, params=None, allow_all=False, **options):
    args = request.args if params is None else params
    if not any(item["id"] == workspace_id for item in store.workspaces(parent_id)):
        raise store.TeamAdminError("工作区不存在", status=404)
    try:
        page = int(args.get("page", 1))
        size = None if allow_all and args.get("page_size") == "all" else int(args.get("page_size", 100))
    except (ValueError, TypeError):
        raise store.TeamAdminError("分页参数无效") from None
    if not 1 <= page <= 100000 or (size is not None and not 1 <= size <= 100):
        raise store.TeamAdminError("分页参数超出范围")
    if size is None:
        page = 1
    return jsonify(read_page(
        parent_id, workspace_id, page=page, page_size=size,
        query=str(args.get("q") or "")[:254], **options,
    ))


@blueprint.post("/parents/<int:parent_id>/jobs")
def enqueue(parent_id):
    return jsonify({"ok": True, "job": service.enqueue(parent_id, _body())}), 202


@blueprint.get("/jobs/<job_id>")
def job_detail(job_id):
    return jsonify(store.get_job(job_id))


@blueprint.post("/jobs/<job_id>/cancel")
def cancel(job_id):
    job = store.get_job(job_id)
    if job["status"] not in {"queued", "running"}:
        raise store.TeamAdminError("任务已结束", status=409)
    store.update_job(job_id, cancel_requested=True, message="等待当前请求结束后取消")
    if job.get("kind") == "schedule":
        from core import team_schedule_service
        team_schedule_service.cancel(job_id)
    return jsonify({"ok": True})


def register_team_admin(app):
    app.register_blueprint(blueprint)
    store.recover_interrupted()
    from core import team_schedule_service
    team_schedule_service.refresh_waiting()
