package io.security.corespringsecurity.security.manager;

import io.security.corespringsecurity.service.SecurityResourceService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    private static final AuthorizationDecision DENY = new AuthorizationDecision(false);
    private final SecurityResourceService securityResourceService;
    private List<RequestMatcherEntry<Set<String>>> mappings = new ArrayList<>();

    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();


    private List<RequestMatcher> permitAlls = new ArrayList<>();

    private List<RequestMatcher> deniedIps=new ArrayList<>();
    private final Log logger = LogFactory.getLog(getClass());

    public void setPermitAlls(List<RequestMatcher> permitAlls) {
        this.permitAlls = permitAlls;
    }

    public void setDeniedIps(List<RequestMatcher> deniedIps) {
        this.deniedIps = deniedIps;
    }

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        Assert.notNull(roleHierarchy, "roleHierarchy cannot be null");
        this.roleHierarchy = roleHierarchy;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
        if (this.logger.isTraceEnabled())
            this.logger.trace(LogMessage.format("Authorizing %s", request));


        for (RequestMatcher ipMatcher : deniedIps) {
            if(ipMatcher.matches(request))
                return DENY;
        }

        for(RequestMatcher permitMatcher: permitAlls)
            if(permitMatcher.matches(request))
                return new AuthorizationDecision(true);

        mappings = securityResourceService.getResourceList();

        for (RequestMatcherEntry<Set<String>> mapping : this.mappings) {
            RequestMatcher matcher = mapping.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request);
            if (matchResult.isMatch()) {
                Set<String> authorities=mapping.getEntry();
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace(LogMessage.format("Checking authorization on %s", request));
                }
                boolean granted = isGranted(authentication.get(),authorities);
                return new AuthorizationDecision(granted);
            }
        }
        if (this.logger.isTraceEnabled()) {
            this.logger.trace(LogMessage.of(() -> "Denying request since did not find matching RequestMatcher"));
        }
        return DENY;
    }

    private boolean isGranted(Authentication authentication,Set<String> authorities) {
        return authentication != null && authentication.isAuthenticated() && isAuthorized(authentication,authorities);
    }

    private boolean isAuthorized(Authentication authentication,Set<String> authorities) {
        for (GrantedAuthority grantedAuthority : getGrantedAuthorities(authentication)) {
            if (authorities.contains(grantedAuthority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    private Collection<? extends GrantedAuthority> getGrantedAuthorities(Authentication authentication) {
        return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
    }



}
