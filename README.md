# saml-test

## 配置说明
<div align="center">

| 字段                   | 作用                                                                                                   |
|----------------------|------------------------------------------------------------------------------------------------------|
| enable               | 是否启用saml功能. 默认为false, 不启用                                                                            |
| entity-id            | 必填, 自定义, 然后提交给SAML供应商, 让对方注册. 任意字符串即可                                                                |
| idp-path             | 必填, SAML供应商提供给我们, 一段xml格式. 放置到指定路径, 如果是外置, 用file: 开头. 如果是内置, 用classpath: 开头                          |
| entity-base-url      | 必填. 域名, 不包含context-path                                                                              |
| jks-path             | 必填. 证书. SAML供应商提供给我们, 并执行一段命令. 下文会展示. 如果是外置, 用file: 开头. 如果是内置, 用classpath: 开头                        |
| store-pass           | 必填. 生成key store的密钥命令, 下文会展示                                                                          |
| private-key-name     | 必填. key store alias                                                                                  |
| private-key-pass     | 必填. key store keypass                                                                                |
| success-redirect-url | 必填. 当SAML登录成功并且回调我们成功后的重定向地址, 此时系统会在url后面拼接token=$token                                              |
| fail-redirect-url    | 选填.当SAML登录成功并且回调我们失败后的重定向地址, 此时系统会在url后面拼接msg=$msg, 指明当前错误信息. 如果当前值为空, 则使用success-redirect-url       |
| sso-url              | 选填. 当SAML登录成功回调我们的地址. 默认为/saml/SSO, 如果自定义需要以/saml开头, 并将域名 + context-path + sso-url提交给SAML供应商, 让对方注册  |

</div>

## 生成JKS

需要第三方提供的东西:
1. okta.cert 文件
2. idp 文件
3. entity id 字符串
4. sso url 回调地址字符串
 
<div>
keytool -genkeypair -alias lifecycle -keypass 123456 -keyalg RSA -keystore okta.jks

keytool -import -v -trustcacerts -keystore okta.jks -file okta.cert
</div>