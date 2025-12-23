package com.example.Internship_System.auth.handler;

import com.example.Internship_System.auth.entity.User;
import com.example.Internship_System.auth.entity.UserStatus;
import com.example.Internship_System.config.JwtUtils;
import com.example.Internship_System.intern.entity.ContractDocument;
import com.example.Internship_System.intern.entity.InternProfile;
import com.example.Internship_System.repository.ContractDocumentRepository;
import com.example.Internship_System.repository.InternRepository;
import com.example.Internship_System.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final InternRepository internRepository;
    private final ContractDocumentRepository contractDocumentRepository;

    public OAuth2LoginSuccessHandler(JwtUtils jwtUtils,UserRepository userRepository,
                                     InternRepository internRepository, ContractDocumentRepository contractDocumentRepository) {
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.internRepository = internRepository;
        this.contractDocumentRepository = contractDocumentRepository;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        var oauthToken = (org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken) authentication;
        var attributes = oauthToken.getPrincipal().getAttributes();

        String email = (String) attributes.get("email");
        if (email == null) {
            throw new IllegalStateException("OAuth2 login failed: email not found");
        }
        String fullNameAttr = (String) attributes.get("name");

        // Lookup user in DB FIRST
        Optional<User> existingUser = userRepository.findByEmail(email);



        // Extract role as before
        String rawRole = authentication.getAuthorities().stream()
                .findFirst()
                .map(Object::toString)
                .orElse("INTERN");
        String role = rawRole.equalsIgnoreCase("OAUTH2_USER") ? "INTERN" : rawRole;

        Integer userId = existingUser.map(User::getUserId).orElse(null);
        String fullName = existingUser.map(User::getFullName).orElse(fullNameAttr != null ? fullNameAttr : "Unknown");

        // ---- NEW CLAIMS ----
        String userStatus = existingUser.map(u -> u.getStatus().toString()).orElse(null);
        String internStatus = null;
        String internConfirmStatus = null;

        if (role.equalsIgnoreCase("INTERN") && userId != null) {

            InternProfile intern = internRepository.findByUserId(userId).orElse(null);
            if (intern != null) {
                internStatus = intern.getStatus().toString();

                ContractDocument doc = contractDocumentRepository
                        .findByIntern(intern)
                        .orElse(null);

                if (doc != null) {
                    internConfirmStatus = doc.getInternConfirmStatus().toString();
                }
            }
        }

        // Generate JWT normally
        String token = jwtUtils.generateToken(email, role, userId, fullName, userStatus, internStatus, internConfirmStatus);

        // Set cookie
        boolean isProd = System.getenv("FRONTEND_URL") != null;
        Cookie cookie = new Cookie("token", token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(isProd);
        cookie.setMaxAge(24 * 60 * 60);
        cookie.setAttribute("SameSite", isProd ? "None" : "Lax");
        response.addCookie(cookie);

        // Redirect to frontend success
        String frontendUrl = System.getenv("FRONTEND_URL");
        if (frontendUrl == null) {
            frontendUrl = "http://localhost:5173";
        }

        String redirectUrl = frontendUrl + "/oauth-success?token=" + token;
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }


}
