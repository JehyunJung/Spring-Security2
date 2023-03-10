package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class UserController {
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;

	private final RoleRepository roleRepository;



	@GetMapping(value="/mypage")
	public String myPage(@AuthenticationPrincipal Account account, Authentication authentication, Principal principal) throws Exception {
		return "user/mypage";
	}
}
