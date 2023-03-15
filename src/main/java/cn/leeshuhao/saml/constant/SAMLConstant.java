package cn.leeshuhao.saml.constant;

/**
 * <p>SAML 常量</p>
 *
 * @author MrLee
 */
public interface SAMLConstant {
    /**
     * SAML 登录验证确认接口
     */
    String CONFIRM_URL = "/saml/confirm";

    /**
     * SAML登录成功回调地址
     */
    String SSO_URL = "/saml/SSO";

    String HTTP_PARAM_TOKEN_PREFIX = "?token=";

    String HTTP_PARAM_ERR_MSG_PREFIX = "?error_message=";
}
