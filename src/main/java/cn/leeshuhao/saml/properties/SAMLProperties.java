package cn.leeshuhao.saml.properties;

import cn.leeshuhao.saml.constant.SAMLConstant;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * <p>SAML 相关配置</p>
 *
 * @author MrLee
 */
@Component
@ConfigurationProperties(prefix = "saml")
@ConditionalOnProperty(prefix = "saml", name = "enable", havingValue = "true")
public class SAMLProperties {
    /**
     * entity id
     */
    private String entityId;

    /**
     * idp
     */
    private String idpPath;

    /**
     * domain url
     *
     */
    private String entityBaseUrl;

    /**
     * java key store path
     */
    private String jksPath;

    /**
     * generate jks store pass
     */
    private String storePass;

    /**
     * jks alias
     */
    private String privateKeyName;

    /**
     * jks key pass
     */
    private String privateKeyPass;

    /**
     * 登录失败重定向地址
     */
    private String failRedirectUrl;

    /**
     * 登录成功重定向地址
     */
    private String successRedirectUrl;

    /**
     * saml 校验成功后回调路径
     */
    private String ssoUrl = SAMLConstant.SSO_URL;

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getIdpPath() {
        return idpPath;
    }

    public void setIdpPath(String idpPath) {
        this.idpPath = idpPath;
    }

    public String getEntityBaseUrl() {
        return entityBaseUrl;
    }

    public void setEntityBaseUrl(String entityBaseUrl) {
        this.entityBaseUrl = entityBaseUrl;
    }

    public String getJksPath() {
        return jksPath;
    }

    public void setJksPath(String jksPath) {
        this.jksPath = jksPath;
    }

    public String getStorePass() {
        return storePass;
    }

    public void setStorePass(String storePass) {
        this.storePass = storePass;
    }

    public String getPrivateKeyName() {
        return privateKeyName;
    }

    public void setPrivateKeyName(String privateKeyName) {
        this.privateKeyName = privateKeyName;
    }

    public String getPrivateKeyPass() {
        return privateKeyPass;
    }

    public void setPrivateKeyPass(String privateKeyPass) {
        this.privateKeyPass = privateKeyPass;
    }

    public String getFailRedirectUrl() {
        return failRedirectUrl;
    }

    public void setFailRedirectUrl(String failRedirectUrl) {
        this.failRedirectUrl = failRedirectUrl;
    }

    public String getSuccessRedirectUrl() {
        return successRedirectUrl;
    }

    public void setSuccessRedirectUrl(String successRedirectUrl) {
        this.successRedirectUrl = successRedirectUrl;
    }

    public String getSsoUrl() {
        return ssoUrl;
    }

    public void setSsoUrl(String ssoUrl) {
        this.ssoUrl = ssoUrl;
    }

    @Override
    public String toString() {
        return "SAMLProperties{" +
                "entityId='" + entityId + '\'' +
                ", idpPath='" + idpPath + '\'' +
                ", entityBaseUrl='" + entityBaseUrl + '\'' +
                ", jksPath='" + jksPath + '\'' +
                ", storePass='" + storePass + '\'' +
                ", privateKeyName='" + privateKeyName + '\'' +
                ", privateKeyPass='" + privateKeyPass + '\'' +
                ", failRedirectUrl='" + failRedirectUrl + '\'' +
                ", successRedirectUrl='" + successRedirectUrl + '\'' +
                ", ssoUrl='" + ssoUrl + '\'' +
                '}';
    }
}
