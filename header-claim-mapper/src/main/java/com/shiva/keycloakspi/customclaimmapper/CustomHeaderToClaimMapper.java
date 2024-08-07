package com.shiva.keycloakspi.customclaimmapper;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CustomHeaderToClaimMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger logger = Logger.getLogger(CustomHeaderToClaimMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final String HEADER_NAME = "header.name";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        ProviderConfigProperty headerNameProperty = new ProviderConfigProperty();
        headerNameProperty.setName(HEADER_NAME);
        headerNameProperty.setLabel("Header Name");
        headerNameProperty.setType(ProviderConfigProperty.STRING_TYPE);
        headerNameProperty.setHelpText("Name of the header to extract the claim from");
        configProperties.add(headerNameProperty);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomHeaderToClaimMapper.class);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    private String extractClaim(ProtocolMapperModel mappingModel, KeycloakSession keycloakSession) {
        String headerName = mappingModel.getConfig().get(HEADER_NAME);
        logger.info("Extracting claim from header: " + headerName);

        List<String> headerValueList = keycloakSession.getContext().getRequestHeaders().getRequestHeaders().get(headerName);
        if (headerValueList == null || headerValueList.isEmpty()) {
            logger.info("Header " + headerName + " not found.");
            return null;
        }

        String claimJsonStr = headerValueList.get(0); // Use the header value as plain text
        logger.info("Header value retrieved: " + claimJsonStr);

        return claimJsonStr;
    }


    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
                                            KeycloakSession session, UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        // Extract the claim and add it to the token
        String headerName = mappingModel.getConfig().get(HEADER_NAME);
        String customClaimValue = extractClaim(mappingModel, session);
        if (customClaimValue != null) {
            Map<String, Object> claims = token.getOtherClaims();
            claims.put(headerName, customClaimValue);
        }

        return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
    }

    @Override
    public String getId() {
        return "final-custom-header-to-claim-mapper";
    }

    @Override
    public String getDisplayType() {
        return "final Custom custom Header to Claim Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getHelpText() {
        return "Maps a claim from a custom header into the token.";
    }

    @Override
    public String getProtocol() {
        return "openid-connect";
    }
}
