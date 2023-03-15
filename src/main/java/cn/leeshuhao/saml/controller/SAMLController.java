package cn.leeshuhao.saml.controller;

import cn.hutool.core.net.URLEncodeUtil;
import cn.leeshuhao.saml.properties.SAMLProperties;
import cn.leeshuhao.saml.constant.SAMLConstant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 *
 * @author MrLee
 */
@Controller
@RequestMapping("/saml")
public class SAMLController {
    private static final Logger logger = LoggerFactory.getLogger(SAMLController.class);

    private SAMLProperties samlProperties;

    public SAMLController(SAMLProperties samlProperties) {
        this.samlProperties = samlProperties;
    }

    @RequestMapping(value = "/confirm")
    public String confirm() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        if (StringUtils.hasText(currentPrincipalName)) {
            try {
                // TODO authenticate and add token in url suffix
                return "redirect:" + samlProperties.getSuccessRedirectUrl() + SAMLConstant.HTTP_PARAM_TOKEN_PREFIX;
            } catch (Exception e) {
                logger.error(e.getMessage(), e);

                if (StringUtils.hasText(samlProperties.getFailRedirectUrl())) {
                    return "redirect:" + samlProperties.getFailRedirectUrl() + SAMLConstant.HTTP_PARAM_ERR_MSG_PREFIX + URLEncodeUtil.encode(e.getMessage());
                } else {
                    return "redirect:" + samlProperties.getSuccessRedirectUrl() + SAMLConstant.HTTP_PARAM_ERR_MSG_PREFIX + URLEncodeUtil.encode(e.getMessage());
                }
            }
        } else {
            if (StringUtils.hasText(samlProperties.getFailRedirectUrl())) {
                return "redirect:" + samlProperties.getFailRedirectUrl();
            } else {
                return "redirect:" + samlProperties.getSuccessRedirectUrl();
            }
        }
    }
}
