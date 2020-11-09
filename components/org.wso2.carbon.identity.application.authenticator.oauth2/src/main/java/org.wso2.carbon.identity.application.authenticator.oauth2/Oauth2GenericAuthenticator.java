/*******************************************************************************
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 ******************************************************************************/
package org.wso2.carbon.identity.application.authenticator.oauth2;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/***
 * Oauth2GenericAuthenticator supports federating authentication with External Oauth IDP s from WSO2 IAM.
 */
public class Oauth2GenericAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 8654763286341993633L;
    private static final Log logger = LogFactory.getLog(Oauth2GenericAuthenticator.class);
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String userInfoEndpoint;
    private String stateToken;

    private static final String DYNAMIC_PARAMETER_LOOKUP_REGEX = "\\$\\{(\\w+)\\}";
    private static Pattern pattern = Pattern.compile(DYNAMIC_PARAMETER_LOOKUP_REGEX);

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("initiateAuthenticationRequest");
        }

        String stateToken = generateState();
        this.stateToken = stateToken;

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
            String callbackUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
            String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
            String scope = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.SCOPE);
            String state = stateToken + "," + Oauth2GenericAuthenticatorConstants.OAUTH2_LOGIN_TYPE;

            context.setContextIdentifier(stateToken);


            String queryString = getQueryString(authenticatorProperties);
            queryString = interpretQueryString(queryString, request.getParameterMap());
            Map<String, String> paramValueMap = new HashMap<>();

            if (StringUtils.isNotBlank(queryString)) {
                String[] params = queryString.split("&");
                for (String param : params) {
                    String[] intParam = param.split("=");
                    if (intParam.length >= 2) {
                        paramValueMap.put(intParam[0], intParam[1]);
                    }
                }
            }

            OAuthClientRequest authzRequest;

            if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("scope=") && queryString
                    .toLowerCase().contains("redirect_uri=")) {
                authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setResponseType(Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state)
                        .buildQueryMessage();
            } else if (StringUtils.isNotBlank(queryString) && queryString.toLowerCase().contains("scope=")) {
                authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callbackUrl)
                        .setResponseType(Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state)
                        .buildQueryMessage();
            } else {
                authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callbackUrl)
                        .setResponseType(Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setScope(scope)
                        .setState(state)
                        .buildQueryMessage();
            }

            String loginPage = authzRequest.getLocationUri();
            String domain = request.getParameter("domain");

            if (StringUtils.isNotBlank(domain)) {
                loginPage = loginPage + "&fidp=" + domain;
            }

            if (StringUtils.isNotBlank(queryString)) {
                if (!queryString.startsWith("&")) {
                    loginPage = loginPage + "&" + queryString;
                } else {
                    loginPage = loginPage + queryString;
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug(String.join("Authorization Request",authzRequest.getLocationUri()));
            }

            logger.info("MBRLIAMSUB-4  Additional Logs : Authorized Request URL : "  + loginPage);

            response.sendRedirect(loginPage);

        } catch (IOException e) {
            logger.error("Exception while sending to the login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            logger.error("Exception while building authorization code request.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("processAuthenticationResponse");
        }

        if (isOauth2ErrorParamExists(request)) {
            if (logger.isDebugEnabled()) {
                logger.debug("OAuth error received from federated IdP: "
                        + request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_ERROR));
            }
            throw new AuthenticationFailedException("Authentication failed.");
        }

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
            String redirectUri = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
            Boolean basicAuthEnabled = Boolean.parseBoolean(
                    authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED));
            String code = getAuthorizationCode(request);

            logger.info("MBRLIAMSUB-4  Additional Logs : Received Authorization Code : "  + code);

            String tokenEP = getTokenEndpoint(authenticatorProperties);
            String token = getToken(tokenEP, clientId, clientSecret, code, redirectUri, basicAuthEnabled);
            String userInfoEP = getUserInfoEndpoint(authenticatorProperties);
            String responseBody = getUserInfo(userInfoEP, token);

            logger.info("MBRLIAMSUB-4  Additional Logs : UserInfo Response : "  + responseBody);

            if (logger.isDebugEnabled()) {
                logger.debug("Get user info response : " + responseBody);
            }

            buildClaims(context, responseBody);
        } catch (ApplicationAuthenticatorException e) {
            logger.error("Failed to process Connect response.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

    }



    protected void initiateLogoutRequest(HttpServletRequest request,
                                         HttpServletResponse response, AuthenticationContext context)
            throws LogoutFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
//        boolean logoutEnabled = Boolean.parseBoolean(
//                authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.IS_LOGOUT_ENABLED));

        boolean logoutEnabled = true;

        if (logoutEnabled) {
            //send logout request to external idp
            String idpLogoutURL =
                    authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_LOGOUT_URL);

            logger.info("MBRLIAMSUB-24  Logout enabled & Logout URL : "  + idpLogoutURL);

            if (idpLogoutURL == null || idpLogoutURL.trim().length() == 0) {
                throw new LogoutFailedException(
                        "Logout is enabled for the IdP but Logout URL is not configured");
            }

            try {
                    response.sendRedirect(idpLogoutURL);
            } catch (IOException e) {
                logger.error(e);
                throw new LogoutFailedException(e.getMessage(), e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request,
                                         HttpServletResponse response, AuthenticationContext context)
            throws LogoutFailedException {

        logger.info("MBRLIAMSUB-24  Logout response is received ");
        throw new UnsupportedOperationException();
    }




    protected void buildClaims(AuthenticationContext context, String userInfoString)
            throws ApplicationAuthenticatorException, AuthenticationFailedException {

        if (userInfoString != null) {
            Map<String, Object> userInfoJson = JSONUtils.parseJSON(userInfoString);

            if (logger.isDebugEnabled()) {
                logger.debug("buildClaims");
            }

            Map<ClaimMapping, String> claims = new HashMap<>();

            for (Map.Entry<String, Object> entry : userInfoJson.entrySet()) {
                claims.put(
                        ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                        entry.getValue().toString());
                if (logger.isDebugEnabled()
                        && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    logger.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                            + entry.getValue());
                }
            }

            if (StringUtils
                    .isBlank(context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
                context.getExternalIdP().getIdentityProvider().getClaimConfig()
                        .setUserClaimURI(Oauth2GenericAuthenticatorConstants.EMAIL);
            }
            String subjectFromClaims = FrameworkUtils
                    .getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
            if (StringUtils.isNotBlank(subjectFromClaims)) {
                AuthenticatedUser authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                context.setSubject(authenticatedUser);
            } else {
                setSubject(context, userInfoJson);
            }
            context.getSubject().setUserAttributes(claims);

        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Decoded json object is null");
            }
            logger.error("Decoded json object is null");
            throw new AuthenticationFailedException("Decoded json object is null");
        }
    }

    protected void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {

        String authenticatedUserId = jsonObject.get(Oauth2GenericAuthenticatorConstants.DEFAULT_USER_IDENTIFIER)
                .toString();

        logger.info("MBRLIAMSUB-4  Additional Logs : Username from UserInfo Response: "  + authenticatedUserId);

        if (StringUtils.isEmpty(authenticatedUserId)) {
            logger.error("Authenticated user identifier is empty");
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        context.setSubject(authenticatedUser);
    }

    protected String getToken(String tokenEndPoint, String clientId, String clientSecret, String code,
                              String redirectUri, Boolean basicAuthEnabled)
            throws ApplicationAuthenticatorException, AuthenticationFailedException {

        String state = this.stateToken;
        OAuthClientRequest tokenRequest =
                buidTokenRequest(tokenEndPoint, clientId, clientSecret, state, code, redirectUri, basicAuthEnabled);

        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, tokenRequest);

        String token =  oAuthResponse.getParam(Oauth2GenericAuthenticatorConstants.ACCESS_TOKEN);

        logger.info("MBRLIAMSUB-4  Additional Logs : Access Token  : "  + token);

        if (StringUtils.isBlank(token)) {
            logger.error("Received access token is invalid : " + token);
            throw new ApplicationAuthenticatorException("Received access token is invalid.");
        }
        return token;
    }

    protected String getAuthorizationCode(HttpServletRequest request) throws ApplicationAuthenticatorException {

        OAuthAuthzResponse authzResponse;
        try {
            authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            return authzResponse.getCode();
        } catch (OAuthProblemException e) {
            logger.error(e);
            throw new ApplicationAuthenticatorException("Exception while reading authorization code.", e);
        }
    }

    protected String sendRequest(String url) throws IOException {

        BufferedReader bufferReader = null;
        StringBuilder stringBuilder = new StringBuilder();

        try {
            URLConnection urlConnection = new URL(url).openConnection();
            bufferReader = new BufferedReader(
                    new InputStreamReader(urlConnection.getInputStream(), StandardCharsets.UTF_8));

            String inputLine = bufferReader.readLine();
            while (inputLine != null) {
                stringBuilder.append(inputLine).append(Oauth2GenericAuthenticatorConstants.NEW_LINE);
                inputLine = bufferReader.readLine();
            }
        } finally {
            IdentityIOStreamUtils.closeReader(bufferReader);
        }
        return stringBuilder.toString();
    }

    protected OAuthClientRequest buidTokenRequest(String tokenEndPoint, String clientId, String clientSecret,
                                                  String state, String code, String redirectUri,
                                                  Boolean basicAuthEnabled) throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest;
        try {
            if (!basicAuthEnabled) {
                tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setClientId(clientId)
                        .setClientSecret(clientSecret)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setCode(code)
                        .setRedirectURI(redirectUri)
                        .setParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE, state)
                        .buildBodyMessage();
            } else {
                tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setCode(code)
                        .setRedirectURI(redirectUri)
                        .setParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE, state)
                        .buildBodyMessage();

                String base64EncodedCredential =
                        new String(Base64.encodeBase64((clientId + Oauth2GenericAuthenticatorConstants.COLON +
                                clientSecret).getBytes()));
                tokenRequest.addHeader(OAuth.HeaderType.AUTHORIZATION,
                        Oauth2GenericAuthenticatorConstants.AUTH_TYPE + base64EncodedCredential);
            }
        } catch (OAuthSystemException e) {
            logger.error(e);
            throw new ApplicationAuthenticatorException("Exception while building access token request.", e);
        }

        logger.info("MBRLIAMSUB-4  Additional Logs : Token Request Body URL : "  + tokenRequest.getBody());

        return tokenRequest;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName(Oauth2GenericAuthenticatorConstants.CLIENT_ID_DP);
        clientId.setRequired(true);
        clientId.setDescription(Oauth2GenericAuthenticatorConstants.CLIENT_ID_DESC);
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET_DP);
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET_DESC);
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DP);
        callbackUrl.setRequired(true);
        callbackUrl.setDescription(Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DESC);
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property authorizationUrl = new Property();
        authorizationUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        authorizationUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL_DP);
        authorizationUrl.setRequired(true);
        authorizationUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL_DESC);
        authorizationUrl.setDisplayOrder(4);
        configProperties.add(authorizationUrl);

        Property tokenUrl = new Property();
        tokenUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        tokenUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL_DP);
        tokenUrl.setRequired(true);
        tokenUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL_DESC);
        tokenUrl.setDisplayOrder(5);
        configProperties.add(tokenUrl);

        Property userInfoUrl = new Property();
        userInfoUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        userInfoUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL_DP);
        userInfoUrl.setRequired(true);
        userInfoUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL_DESC);
        userInfoUrl.setDisplayOrder(6);
        configProperties.add(userInfoUrl);

        Property scope = new Property();
        scope.setName(Oauth2GenericAuthenticatorConstants.SCOPE);
        scope.setDisplayName(Oauth2GenericAuthenticatorConstants.SCOPE_DP);
        scope.setRequired(false);
        scope.setDescription(Oauth2GenericAuthenticatorConstants.SCOPE_DESC);
        scope.setDisplayOrder(7);
        configProperties.add(scope);

        Property enableBasicAuth = new Property();
        enableBasicAuth.setName(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED);
        enableBasicAuth.setDisplayName(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DP);
        enableBasicAuth.setRequired(false);
        enableBasicAuth.setDescription(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DESC);
        enableBasicAuth.setType(Oauth2GenericAuthenticatorConstants.VAR_TYPE_BOOLEAN);
        enableBasicAuth.setDisplayOrder(8);
        configProperties.add(enableBasicAuth);


//        Property enableLogout = new Property();
//        enableLogout.setName(Oauth2GenericAuthenticatorConstants.IS_LOGOUT_ENABLED);
//        enableLogout.setDisplayName(Oauth2GenericAuthenticatorConstants.IS_LOGOUT_ENABLED_DP);
//        enableLogout.setRequired(false);
//        enableLogout.setDescription(Oauth2GenericAuthenticatorConstants.IS_LOGOUT_ENABLED_DESC);
//        enableLogout.setType(Oauth2GenericAuthenticatorConstants.VAR_TYPE_BOOLEAN);
//        enableLogout.setDisplayOrder(9);
//        configProperties.add(enableLogout);

        Property logoutUrl = new Property();
        logoutUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_LOGOUT_URL);
        logoutUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_LOGOUT__URL_DP);
        logoutUrl.setRequired(false);
        logoutUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_USER_LOGOUT__URL_DESC);
        logoutUrl.setDisplayOrder(9);
        configProperties.add(logoutUrl);

        Property additionalParams = new Property();
        additionalParams.setName("commonAuthQueryParams");
        additionalParams.setDisplayName("Additional Query Parameters");
        additionalParams.setRequired(false);
        additionalParams.setDescription("Additional query parameters. e.g: paramName1=value1");
        additionalParams.setType("string");
        additionalParams.setDisplayOrder(11);
        configProperties.add(additionalParams);


        return configProperties;
    }

    protected String getUserInfo(String apiUrl, String token) {

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(Oauth2GenericAuthenticatorConstants.AUTH_HEADER_NAME,
                Oauth2GenericAuthenticatorConstants.TOKEN_TYPE+ token);

        HttpURLConnection con = connect(apiUrl);
        try {
            con.setRequestMethod(Oauth2GenericAuthenticatorConstants.HTTP_GET_METHOD);
            for (Map.Entry<String, String> header : requestHeaders.entrySet())
                con.setRequestProperty(header.getKey(), header.getValue());

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readBody(con.getInputStream());
            } else {
                return readBody(con.getErrorStream());
            }
        } catch (IOException e) {
            logger.error(e);
            throw new RuntimeException("API Invoke failed", e);
        } finally {
            con.disconnect();
        }
    }


    protected OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Exception while requesting access token", e);
            }
            logger.error(e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return oAuthResponse;
    }

    protected HttpURLConnection connect(String apiUrl) {

        try {
            URL url = new URL(apiUrl);
            return (HttpURLConnection) url.openConnection();
        } catch (MalformedURLException e) {
            logger.error(e);
            throw new RuntimeException("API URL is Invalid. : " + apiUrl, e);
        } catch (IOException e) {
            logger.error(e);
            throw new RuntimeException("Connection failed. : " + apiUrl, e);
        }
    }

    protected String readBody(InputStream body) {

        InputStreamReader streamReader = new InputStreamReader(body);

        try (BufferedReader lineReader = new BufferedReader(streamReader)) {
            StringBuilder responseBody = new StringBuilder();

            String line;
            while ((line = lineReader.readLine()) != null) {
                responseBody.append(line);
            }

            return responseBody.toString();
        } catch (IOException e) {
            logger.error(e);
            throw new RuntimeException("API Failed to read response.", e);
        }
    }

    protected boolean isOauth2CodeParamExists(HttpServletRequest request) {

        return request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null;
    }

    protected boolean isOauth2ErrorParamExists(HttpServletRequest request) {

        return request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_ERROR) != null;
    }

    protected String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotBlank(state) && state.split(",").length > 1) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    protected boolean isOauthStateParamExists(HttpServletRequest request) {

        return request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE) != null
                && Oauth2GenericAuthenticatorConstants.OAUTH2_LOGIN_TYPE.equals(getLoginType(request));
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isOauthStateParamExists(request) && (isOauth2CodeParamExists(request)
                || isOauth2ErrorParamExists(request));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String state;
        try {
            state = OAuthAuthzResponse.oauthCodeAuthzResponse(request).getState();
            return state.split(",")[0];
        } catch (OAuthProblemException e1) {
            logger.error("No context");
            e1.printStackTrace();
            return null;
        } catch (IndexOutOfBoundsException e2) {
            logger.error("No state returned");
            e2.printStackTrace();
            return null;
        }
    }

    protected String generateState() {

        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }

    @Override
    public String getFriendlyName() {

        return Oauth2GenericAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return Oauth2GenericAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    protected void initTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        if (StringUtils.isEmpty(tokenUrl)) {
            this.tokenEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        } else {
            this.tokenEndpoint = tokenUrl;
        }
    }

    protected void initOAuthEndpoint(Map<String, String> authenticatorProperties) {

        String oAuthUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        if (StringUtils.isEmpty(oAuthUrl)) {
            this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        } else {
            this.oAuthEndpoint = oAuthUrl;
        }
    }

    protected void initUserInfoEndPoint(Map<String, String> authenticatorProperties) {

        String userInfoUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        if (StringUtils.isEmpty(userInfoUrl)) {
            this.userInfoEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        } else {
            this.userInfoEndpoint = userInfoUrl;
        }

    }

    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.tokenEndpoint)) {
            initTokenEndpoint(authenticatorProperties);
        }
        return this.tokenEndpoint;
    }

    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            initOAuthEndpoint(authenticatorProperties);
        }

        return this.oAuthEndpoint;
    }

    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.userInfoEndpoint)) {
            initUserInfoEndPoint(authenticatorProperties);
        }
        return this.userInfoEndpoint;
    }


    protected String getQueryString(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(FrameworkConstants.QUERY_PARAMS);
    }

    private String interpretQueryString(String queryString, Map<String, String[]> parameters) {

        if (StringUtils.isBlank(queryString)) {
            return null;
        }
        Matcher matcher = pattern.matcher(queryString);
        while (matcher.find()) {
            String name = matcher.group(1);
            String[] values = parameters.get(name);
            String value = "";
            if (values != null && values.length > 0) {
                value = values[0];
            }
            try {
                value = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                logger.error("Error while encoding the query param: " + name + " with value: " + value, e);
            }
            if (logger.isDebugEnabled()) {
                logger.debug("InterpretQueryString name: " + name + ", value: " + value);
            }
            queryString = queryString.replaceAll("\\$\\{" + name + "}", Matcher.quoteReplacement(value));
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Output QueryString: " + queryString);
        }
        return queryString;
    }

}

