package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.XOAuthProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

/**
 * RED stub (slice 3): deliberately minimal routes so the real application context has something
 * mapped to {@code /auth/login} and {@code /auth/callback} (not Spring's default 404), letting
 * {@code OAuthLoginFlowTest} exercise real HTTP calls that get real (wrong) responses instead of
 * a context-boot failure. No PKCE state is actually stored server-side, no X token exchange is
 * actually performed -- see docs/slices/03-auth.md, Section 0 for the real flow.
 */
@RestController
public class OAuthLoginController {

    private final XOAuthProperties oAuthProperties;

    public OAuthLoginController(XOAuthProperties oAuthProperties) {
        this.oAuthProperties = oAuthProperties;
    }

    @GetMapping("/auth/login")
    public ResponseEntity<Void> login() {
        String state = UUID.randomUUID().toString();
        URI redirectTo = URI.create(oAuthProperties.authorizeUrl() + "?state=" + state);
        return ResponseEntity.status(302).location(redirectTo).build();
    }

    @GetMapping("/auth/callback")
    public ResponseEntity<String> callback(@RequestParam Map<String, String> params) {
        return ResponseEntity.status(501).body("oauth callback not implemented");
    }
}
