package cn.leeshuhao.saml.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

/**
 *
 * @author MrLee
 */
@Controller
@RequestMapping("saml")
public class SAMLController {
    private static final Logger logger = LoggerFactory.getLogger(SAMLController.class);

    @GetMapping(value = "/home")
    public String home(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (Objects.nonNull(authentication)) {
            model.addAttribute("username", authentication.getName());
        } else {
            model.addAttribute("username", "路人甲");
        }
        return "home";
    }
}
