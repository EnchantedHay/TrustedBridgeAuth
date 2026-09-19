package top.pkumc.trustedbridgeauth;

import java.io.IOException;

/** Only fixed, public reasons may cross the bridge or reach a player. */
final class TransferFailure extends IOException {
    // TBL4 wire IDs are enum ordinals, so existing reasons have fixed positions.
    enum Reason {
        REJECTED("对方服务器拒绝跳转，请重新登录原服务器；仍失败请联系管理员。"),
        BINDING_REQUIRED("请先在 PKUMC 皮肤站绑定此正版账号，再尝试跳转。"),
        LOCAL_ACCOUNT_MISSING("找不到 PKUMC 皮肤站角色，请检查角色和账号绑定。"),
        CHARACTER_REQUIRED("请先在 PKUMC 皮肤站创建角色，再尝试跳转。"),
        CHARACTER_AMBIGUOUS("皮肤站有多个角色，请先登录 PKUMC 的目标角色，再从 PKUMC 跳转。"),
        CHARACTER_CHANGED("原 PKUMC 角色或绑定已变更，请重新登录 PKUMC。"),
        ACCOUNT_UNAVAILABLE("PKUMC 皮肤站账号不可用，请联系管理员。"),
        IDENTITY_UNAVAILABLE("身份验证服务暂不可用，请稍后重试。"),
        PREMIUM_REQUIRED("请使用正版账号重新登录 THUnion 后再跳转。"),
        RELOGIN_REQUIRED("登录信息已失效，请重新登录当前服务器后再跳转。"),
        BUSY("跨服繁忙，请稍后重试。");

        final String message;
        Reason(String message) { this.message = message; }
    }

    final Reason reason;
    TransferFailure(Reason reason) { super(reason.name()); this.reason = reason; }
    static Reason decode(int code) {
        return code >= 0 && code < Reason.values().length ? Reason.values()[code] : Reason.REJECTED;
    }
    static String message(Throwable error, String fallback) {
        for (int i = 0; error != null && i < 8; i++, error = error.getCause())
            if (error instanceof TransferFailure failure) return failure.reason.message;
        return fallback;
    }
}
