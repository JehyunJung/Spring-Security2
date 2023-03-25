package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class AopSecurityController {

    private final AopMethodService aopMethodService;

    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') and #accountDto.username == principal.username")
    public String preAuthorize(AccountDto accountDto, Model model) {
        model.addAttribute("method", "Success @PreAuthorize");
        return "aop/method";
    }

    @GetMapping("/methodSecured")
    public String methodSecured(Model model) {
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success Method Secured");

        return "aop/method";
    }
}
